#[cfg(test)]
mod tests {
    use ergo_wire::codec;
    use ergo_wire::message::MessageCode;

    /// GetPeers is code=1, empty body. Frame should be exactly 9 bytes.
    #[test]
    fn get_peers_frame_testnet() {
        let magic = [2u8, 0, 0, 1];
        let frame = codec::encode_message(&magic, MessageCode::GetPeers as u8, &[]);
        assert_eq!(frame.len(), 9);
        assert_eq!(
            frame,
            vec![
                2, 0, 0, 1, // magic
                1, // GetPeers code
                0, 0, 0, 0, // length = 0
            ]
        );
    }

    /// Verify checksum is first 4 bytes of blake2b256(body)
    #[test]
    fn checksum_correctness() {
        use blake2::digest::consts::U32;
        use blake2::{Blake2b, Digest};
        let magic = [1u8, 0, 2, 4];
        let body = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = codec::encode_message(&magic, MessageCode::Inv as u8, &body);

        let expected_hash = <Blake2b<U32>>::digest(&body);
        let expected_checksum = &expected_hash[..4];

        // checksum starts at byte 9 (after header)
        assert_eq!(&frame[9..13], expected_checksum);
    }
}
