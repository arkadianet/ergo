//! Async TCP connection: framed message reading and writing.
//!
//! Wraps a TcpStream with message framing from `framing.rs`.
//! Provides `read_message()` and `write_message()` that handle
//! frame encoding/decoding, buffering, and checksum verification.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::framing::{self, FrameError, MessageFrame, HEADER_LENGTH};

/// Maximum payload size we'll accept from a peer (8MB — Modifier with ADProof reserve).
const MAX_PAYLOAD_SIZE: usize = 8_194_304;

/// Read buffer size for TCP.
const READ_BUF_SIZE: usize = 65_536;

/// A framed P2P connection over TCP.
pub struct Connection {
    stream: TcpStream,
    magic: [u8; 4],
    read_buf: Vec<u8>,
}

/// Failures produced by [`Connection::read_message`] /
/// [`Connection::write_message`].
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// Underlying TCP I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Frame decoding rejected the bytes.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    /// Peer closed the TCP stream cleanly (read returned 0 bytes).
    #[error("connection closed by peer")]
    Closed,
    /// Frame's declared payload length exceeded `MAX_PAYLOAD_SIZE`.
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    PayloadTooLarge(usize),
}

impl Connection {
    /// Wrap a TcpStream for P2P communication.
    pub fn new(stream: TcpStream, magic: [u8; 4]) -> Self {
        Self {
            stream,
            magic,
            read_buf: Vec::with_capacity(READ_BUF_SIZE),
        }
    }

    /// Wrap a TcpStream with pre-existing buffered data.
    /// Used after handshake when the initial read may contain both the
    /// handshake response AND subsequent framed messages.
    pub fn new_with_buffer(stream: TcpStream, magic: [u8; 4], initial_data: Vec<u8>) -> Self {
        Self {
            stream,
            magic,
            read_buf: initial_data,
        }
    }

    /// Read one complete message frame from the connection.
    ///
    /// Blocks (async) until a full frame is available. Returns the frame's
    /// code and payload. Handles partial reads and buffering internally.
    pub async fn read_message(&mut self) -> Result<MessageFrame, ConnectionError> {
        loop {
            // Try to parse a frame from what we have buffered
            match framing::deserialize_frame(&self.magic, &self.read_buf) {
                Ok(Some((frame, consumed))) => {
                    // Validate size
                    if frame.payload.len() > MAX_PAYLOAD_SIZE {
                        return Err(ConnectionError::PayloadTooLarge(frame.payload.len()));
                    }
                    self.read_buf.drain(..consumed);
                    return Ok(frame);
                }
                Ok(None) => {
                    // Check the declared length from the frame header (if we
                    // have at least 9 bytes) to reject oversized frames early,
                    // before buffering the full payload.
                    if self.read_buf.len() >= HEADER_LENGTH {
                        let declared_len =
                            i32::from_be_bytes(self.read_buf[5..9].try_into().unwrap());
                        if declared_len > MAX_PAYLOAD_SIZE as i32 {
                            self.read_buf.clear();
                            return Err(ConnectionError::PayloadTooLarge(declared_len as usize));
                        }
                    }

                    // Need more data — read from socket
                    let mut tmp = [0u8; READ_BUF_SIZE];
                    let n = self.stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(ConnectionError::Closed);
                    }
                    self.read_buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    return Err(ConnectionError::Frame(e));
                }
            }
        }
    }

    /// Write a message frame to the connection.
    pub async fn write_message(&mut self, frame: &MessageFrame) -> Result<(), ConnectionError> {
        let bytes = framing::serialize_frame(&self.magic, frame);
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    /// Write a message with a specific code and payload.
    pub async fn send(&mut self, code: u8, payload: Vec<u8>) -> Result<(), ConnectionError> {
        self.write_message(&MessageFrame { code, payload }).await
    }

    /// Get a reference to the underlying TcpStream (for address info, etc.).
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Consume the connection and return the TcpStream.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::MAINNET_MAGIC;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn roundtrip_empty_payload() {
        let (mut client, mut server) = connected_pair().await;

        client.send(1, Vec::new()).await.unwrap(); // GetPeers
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg.code, 1);
        assert!(msg.payload.is_empty());
    }

    #[tokio::test]
    async fn roundtrip_with_payload() {
        let (mut client, mut server) = connected_pair().await;

        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        client.send(55, payload.clone()).await.unwrap();
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg.code, 55);
        assert_eq!(msg.payload, payload);
    }

    #[tokio::test]
    async fn multiple_messages() {
        let (mut client, mut server) = connected_pair().await;

        for i in 0..5u8 {
            client
                .send(i + 1, vec![i; (i as usize + 1) * 10])
                .await
                .unwrap();
        }

        for i in 0..5u8 {
            let msg = server.read_message().await.unwrap();
            assert_eq!(msg.code, i + 1);
            assert_eq!(msg.payload.len(), (i as usize + 1) * 10);
        }
    }

    #[tokio::test]
    async fn detects_closed_connection() {
        let (client, mut server) = connected_pair().await;
        drop(client); // close the client side
        let result = server.read_message().await;
        assert!(matches!(result, Err(ConnectionError::Closed)));
    }

    async fn connected_pair() -> (Connection, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        (
            Connection::new(client_stream, MAINNET_MAGIC),
            Connection::new(server_stream, MAINNET_MAGIC),
        )
    }
}
