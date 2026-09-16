//! Direct submission is restricted to an explicitly opted-in devnet.

pub(super) fn enabled(network: ergo_chain_spec::Network, configured: bool) -> bool {
    network == ergo_chain_spec::Network::Devnet && configured
}

#[cfg(test)]
mod tests {
    use super::super::SubmitBridge;
    use ergo_api::traits::NodeSubmit;
    use ergo_chain_spec::Network;

    // ----- helpers -----

    fn bridge(network: Network, configured: bool) -> SubmitBridge {
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let (events, _) = tokio::sync::mpsc::channel(1);
        SubmitBridge::new(tx, events).with_direct_block_submit(network, configured)
    }

    // ----- happy path -----

    #[tokio::test]
    async fn direct_submit_devnet_opted_in_reaches_deserializer() {
        let submit = bridge(Network::Devnet, true);
        assert!(submit.direct_block_submit_enabled());
        let response = ergo_api::compat::blocks::submit_handler(
            axum::extract::State(submit.into_dyn()),
            axum::body::Bytes::new(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    // ----- error paths -----

    #[tokio::test]
    async fn direct_submit_network_and_config_gate_returns_forbidden() {
        for (network, configured) in [
            (Network::Mainnet, true),
            (Network::Testnet, true),
            (Network::Mainnet, false),
            (Network::Testnet, false),
            (Network::Devnet, false),
        ] {
            let submit = bridge(network, configured);
            assert!(!submit.direct_block_submit_enabled());
            let response = ergo_api::compat::blocks::submit_handler(
                axum::extract::State(submit.into_dyn()),
                axum::body::Bytes::new(),
            )
            .await;
            assert_eq!(
                response.status(),
                axum::http::StatusCode::FORBIDDEN,
                "{network:?}, configured={configured}"
            );
        }
    }
    #[tokio::test]
    async fn direct_submit_bridge_disabled_rejects_without_dispatch() {
        let block: ergo_rest_json::ScalaFullBlock = serde_json::from_str(include_str!(
            "../../../test-vectors/mainnet/block_836113.json"
        ))
        .unwrap();
        for (network, configured) in [
            (Network::Mainnet, true),
            (Network::Testnet, true),
            (Network::Mainnet, false),
            (Network::Testnet, false),
            (Network::Devnet, false),
        ] {
            let (tx, mut transactions) = tokio::sync::mpsc::channel(1);
            let (events, mut dispatched) = tokio::sync::mpsc::channel(1);
            let submit =
                SubmitBridge::new(tx, events).with_direct_block_submit(network, configured);
            let error = submit.submit_full_block(block.clone()).await.unwrap_err();
            assert_eq!(error.reason, "direct_block_submit_disabled");
            assert_eq!(error.detail, None);
            assert!(matches!(
                dispatched.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                transactions.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
    }
}
