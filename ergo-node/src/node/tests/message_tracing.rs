// ----- span emission -----

#[test]
fn handle_message_emits_span_with_peer_and_code() {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::fmt::MakeWriter;

    // Per-test capture buffer (CLOSE-event format dumps the span's
    // final field values, catching both entry-time and any late
    // recorded fields).
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let buf_for_subscriber = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf_for_subscriber)
        .finish();

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let payload = req_modifier_payload(99, &[mid(1)]);

    tracing::subscriber::with_default(subscriber, || {
        let _ = handle_message(
            &mut state,
            peer,
            message::CODE_REQUEST_MODIFIER,
            &payload,
            Instant::now(),
        );
    });

    let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    assert!(
        output.contains("msg"),
        "missing msg span name in:\n{output}"
    );
    let peer_str = format!("peer={peer}");
    assert!(
        output.contains(&peer_str),
        "missing {peer_str} in:\n{output}"
    );
    let code_str = format!("code={}", message::CODE_REQUEST_MODIFIER);
    assert!(
        output.contains(&code_str),
        "missing {code_str} in:\n{output}"
    );
}
