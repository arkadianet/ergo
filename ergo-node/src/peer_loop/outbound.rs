//! Per-peer outbound limits. Permits cover queued and currently writing frames.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use ergo_p2p::connection::MAX_PAYLOAD_SIZE;
use ergo_p2p::framing::{wire_len, MessageFrame};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

/// Enough small messages for a header-download burst, independently of bytes.
pub const MAX_MESSAGES: usize = 2048;
/// Retained payload allocations plus framing. Serialization of the current
/// frame can temporarily require one additional MAX_PAYLOAD_SIZE allocation.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

pub struct Sender {
    tx: mpsc::Sender<QueuedFrame>,
    bytes: Arc<Semaphore>,
    stop: watch::Sender<bool>,
}

pub struct Receiver {
    rx: mpsc::Receiver<QueuedFrame>,
    pub(super) stop: watch::Receiver<bool>,
}

pub struct QueuedFrame {
    frame: MessageFrame,
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub struct SendError;

pub fn channel(messages: usize) -> (Sender, Receiver) {
    with_limits(messages, MAX_BYTES)
}

fn with_limits(messages: usize, bytes: usize) -> (Sender, Receiver) {
    let (tx, rx) = mpsc::channel(messages);
    let (stop, stopped) = watch::channel(false);
    (
        Sender {
            tx,
            bytes: Arc::new(Semaphore::new(bytes)),
            stop,
        },
        Receiver { rx, stop: stopped },
    )
}

impl Sender {
    pub fn try_send(&self, frame: MessageFrame) -> Result<(), SendError> {
        let result = (|| {
            if *self.stop.borrow() || frame.payload.len() > MAX_PAYLOAD_SIZE {
                return Err(SendError);
            }
            // Charge allocation capacity, not just initialized length.
            let charge =
                u32::try_from(wire_len(frame.payload.capacity())).map_err(|_| SendError)?;
            let permit = self
                .bytes
                .clone()
                .try_acquire_many_owned(charge)
                .map_err(|_| SendError)?;
            self.tx
                .try_send(QueuedFrame {
                    frame,
                    _permit: permit,
                })
                .map_err(|_| SendError)
        })();
        if result.is_err() {
            // Wake the socket task even when it is blocked writing. Callers
            // that ignore a failed dispatch cannot leave the peer alive.
            let _ = self.stop.send(true);
        }
        result
    }
}

impl Deref for Receiver {
    type Target = mpsc::Receiver<QueuedFrame>;
    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}
impl DerefMut for Receiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rx
    }
}
impl Deref for QueuedFrame {
    type Target = MessageFrame;
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: usize) -> MessageFrame {
        MessageFrame {
            code: 1,
            payload: vec![0; n],
        }
    }

    #[test]
    fn byte_limit_includes_in_flight_frame_and_releases_on_drop() {
        let (tx, mut rx) = with_limits(8, wire_len(32));
        tx.try_send(frame(32)).unwrap();
        let writing = rx.try_recv().unwrap();
        assert_eq!(tx.bytes.available_permits(), 0);
        drop(writing);
        tx.try_send(frame(32)).unwrap();
        assert!(tx.try_send(frame(1)).is_err());
        assert!(*rx.stop.borrow());
        drop(rx);
        assert_eq!(tx.bytes.available_permits(), wire_len(32));
    }

    #[test]
    fn message_limit_is_independent_and_failed_enqueue_releases_permit() {
        let (tx, rx) = with_limits(1, 1000);
        tx.try_send(frame(0)).unwrap();
        assert!(tx.try_send(frame(0)).is_err());
        assert_eq!(tx.bytes.available_permits(), 1000 - wire_len(0));
        assert!(*rx.stop.borrow());
        drop(rx);
        assert_eq!(tx.bytes.available_permits(), 1000);
    }

    #[test]
    fn spare_capacity_is_charged_and_closed_receiver_leaks_no_permits() {
        let (tx, rx) = with_limits(8, 100);
        let mut f = frame(0);
        f.payload.reserve(200);
        assert!(tx.try_send(f).is_err());
        assert_eq!(tx.bytes.available_permits(), 100);
        drop(rx);
        let (tx, rx) = with_limits(8, 100);
        drop(rx);
        assert!(tx.try_send(frame(10)).is_err());
        assert_eq!(tx.bytes.available_permits(), 100);
    }
}
