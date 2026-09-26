pub mod addresses;
pub mod balance;
pub mod boxes;
pub mod lifecycle;
pub mod rewards;
pub mod status;
pub mod transactions;
pub mod tx_construction;

pub use addresses::*;
pub use balance::*;
pub use boxes::*;
pub use lifecycle::*;
pub use rewards::*;
pub use status::*;
pub use transactions::*;
pub use tx_construction::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_balance_shape_round_trips_with_decimal_strings() {
        let value = WalletBalanceDto {
            height: 10,
            nano_erg: NanoErgBreakdownDto {
                confirmed: "10".into(),
                available: "7".into(),
                reserved: "3".into(),
                immature: "0".into(),
            },
            assets: vec![WalletAssetDto {
                token_id: "ab".repeat(32),
                amount: "2".into(),
            }],
            reemission: None,
            unconfirmed: None,
        };
        let json = serde_json::to_value(&value).unwrap();
        assert!(json["nanoErg"]["confirmed"].is_string());
        assert!(json["assets"][0]["amount"].is_string());
        assert_eq!(
            serde_json::from_value::<WalletBalanceDto>(json).unwrap(),
            value
        );
    }

    #[test]
    fn native_tagged_shapes_round_trip() {
        let status = BoxStatusDto::Immature {
            matures_at_height: 20,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["type"], "immature");
        assert_eq!(
            serde_json::from_value::<BoxStatusDto>(json).unwrap(),
            status
        );

        let tx = TxRepr::from_bytes(&[0xde, 0xad]);
        let json = serde_json::to_value(&tx).unwrap();
        assert_eq!(json, serde_json::json!({"type":"bytes","bytes":"dead"}));
        assert_eq!(serde_json::from_value::<TxRepr>(json).unwrap(), tx);
    }

    #[test]
    fn native_strict_requests_keep_their_wire_contract() {
        let request: SignTxRequest =
            serde_json::from_str(r#"{"unsignedTransaction":{"type":"bytes","bytes":"00"}}"#)
                .unwrap();
        assert!(request.external_secrets.is_empty());
        assert!(serde_json::from_str::<SignTxRequest>(
            r#"{"unsignedTransaction":{"type":"bytes","bytes":"00"},"extra":1}"#
        )
        .is_err());
    }
}
