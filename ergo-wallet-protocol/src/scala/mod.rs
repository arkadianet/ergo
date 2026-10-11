pub mod admin_advanced;
pub mod lifecycle;
pub mod multi_sig;
pub mod query;
pub mod scan;
pub mod sending;
pub mod types;

pub use admin_advanced::*;
pub use lifecycle::*;
pub use multi_sig::*;
pub use query::*;
pub use scan::*;
pub use sending::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scala_wallet_types_keep_camel_case_wire_names() {
        let value = WalletTransactionEntry {
            tx_id: "ab".repeat(32),
            block_height: 7,
            block_id: "cd".repeat(32),
            wallet_outputs: vec!["01".into()],
            wallet_inputs: vec![],
            scan_ids: vec![],
        };
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["txId"], "ab".repeat(32));
        assert_eq!(json["blockHeight"], 7);
        assert!(json.get("scanIds").is_none());
        let back: WalletTransactionEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.tx_id, value.tx_id);
        assert_eq!(back.block_height, value.block_height);
        assert_eq!(back.wallet_outputs, value.wallet_outputs);
    }

    #[test]
    fn scala_scan_and_hint_shapes_round_trip() {
        let scan = ScanIdJson { scan_id: 11 };
        assert_eq!(serde_json::to_string(&scan).unwrap(), r#"{"scanId":11}"#);
        let back: ScanIdJson = serde_json::from_str(r#"{"scanId":11}"#).unwrap();
        assert_eq!(back.scan_id, scan.scan_id);

        let message = FirstProverMessageJson::DhTuple {
            a: "01".into(),
            b: "02".into(),
        };
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["op"], "dhtABab");
        assert_eq!(
            serde_json::from_value::<FirstProverMessageJson>(json).unwrap(),
            message
        );
    }
}
