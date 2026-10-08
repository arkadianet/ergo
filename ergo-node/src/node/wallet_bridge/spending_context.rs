use std::sync::Arc;

use ergo_wallet_protocol::chain as wire;
use ergo_wallet_service::engine::SigningView;
use ergo_wallet_service::ChainClientError;

use super::InProcessChainClient;

pub(super) struct SpendingProvider {
    pub snapshot: crate::snapshot::SnapshotHandle,
    pub min_relay_fee_nano_erg: u64,
    pub max_tx_size_bytes: usize,
    pub private_queue: Option<Arc<ergo_mining::private_queue::PrivateTransactionQueue>>,
}

pub(super) fn capture(
    client: &InProcessChainClient,
) -> Result<wire::SpendingContext, ChainClientError> {
    let provider = client
        .spending
        .as_ref()
        .ok_or(ChainClientError::Unsupported)?;
    let state = client.state.as_ref().ok_or(ChainClientError::Unsupported)?;
    let committed = client
        .reader
        .committed_snapshot()
        .map_err(|e| InProcessChainClient::state_error("spending snapshot", e))?
        .ok_or(ChainClientError::Unsupported)?;
    let settings = committed
        .validation_settings()
        .map_err(|e| InProcessChainClient::state_error("adopted settings", e))?;
    let view = super::super::chain_snapshot::ChainSnapshot::from_committed(
        committed,
        state.reemission_rules(),
    )
    .map_err(|e| InProcessChainClient::state_error("spending view", e))?;
    let tip = view.tip();
    let pool = provider.snapshot.load_full();
    if pool.publication_sequence == 0
        || pool.tip.best_full_block.height != tip.height
        || pool.tip.best_full_block.header_id != hex::encode(tip.header_id)
    {
        return Err(ChainClientError::Unavailable(
            "mempool publication does not belong to the committed signing tip".into(),
        ));
    }
    // Charge the hex representation before allocating per-transaction strings.
    // The reserve covers fixed metadata, parameter names, settings and trees;
    // variable headers and reservations are charged separately below.
    let mut wire_bytes = 256 * 1024usize;
    for (_, bytes) in pool.pool_full_txs.iter() {
        charge(
            &mut wire_bytes,
            bytes.len().saturating_mul(2).saturating_add(4),
        )?;
    }
    let headers = view
        .headers()
        .iter()
        .zip(view.header_ids())
        .map(|(header, id)| {
            let bytes = client.header_bytes(id)?;
            charge(
                &mut wire_bytes,
                bytes.len().saturating_mul(2).saturating_add(512),
            )?;
            Ok(wire::ChainHeader {
                height: header.height,
                header_id: hex::encode(id),
                parent_id: hex::encode(header.parent_id.as_bytes()),
                timestamp_unix_ms: header.timestamp,
                header_bytes: hex::encode(bytes),
            })
        })
        .collect::<Result<Vec<_>, ChainClientError>>()?;
    let p = view.active_params();
    let proposed_update = p.proposed_update.serialize();
    let activated_update = p.activated_update.serialize();
    let announced_settings = p.announced_settings.as_ref().map(|s| s.serialize());
    let adopted_settings = settings.update_from_initial.serialize();
    for bytes in [&proposed_update, &activated_update, &adopted_settings]
        .into_iter()
        .chain(announced_settings.as_ref())
    {
        charge(&mut wire_bytes, bytes.len().saturating_mul(2))?;
    }
    if let Some(rules) = view.reemission_rules() {
        charge(
            &mut wire_bytes,
            rules.pay_to_reemission_tree.len().saturating_mul(2),
        )?;
        if let Some(emission) = &rules.emission {
            charge(
                &mut wire_bytes,
                emission.emission_tree.len().saturating_mul(2),
            )?;
        }
    }
    let pre = &view.state_context().sigma_pre_header;
    let (private_queue_revision, private_reserved_inputs) = match provider.private_queue.as_ref() {
        Some(queue) => {
            let (revision, inputs) = queue.reservation_snapshot();
            charge(&mut wire_bytes, inputs.len().saturating_mul(67))?;
            (
                Some(revision),
                inputs.into_iter().map(hex::encode).collect(),
            )
        }
        None => (None, Vec::new()),
    };
    let reemission = view
        .reemission_rules()
        .map(|rules| wire::SpendingReemissionRules {
            check_rules: rules.check_rules,
            activation_height: rules.activation_height,
            reemission_token_id: hex::encode(rules.reemission_token_id),
            pay_to_reemission_tree: hex::encode(&rules.pay_to_reemission_tree),
            emission: rules.emission.as_ref().map(|emission| {
                let m = emission.monetary;
                wire::SpendingEmissionRules {
                    emission_nft_id: hex::encode(emission.emission_nft_id),
                    emission_tree: hex::encode(&emission.emission_tree),
                    monetary: wire::SpendingMonetaryParameters {
                        fixed_rate: m.fixed_rate,
                        fixed_rate_period: m.fixed_rate_period,
                        epoch_length: m.epoch_length,
                        one_epoch_reduction: m.one_epoch_reduction,
                        founders_initial_reward: m.founders_initial_reward,
                        miner_reward_delay: m.miner_reward_delay,
                    },
                }
            }),
        });
    client.ensure_tip_unchanged(&tip)?;
    Ok(wire::SpendingContext {
        version: wire::SPENDING_CONTEXT_VERSION,
        network: pool.info.network.clone(),
        tip: super::wire_tip(tip).map_err(|e| ChainClientError::Protocol(e.to_string()))?,
        headers,
        pre_header: wire::SpendingPreHeader {
            version: pre.version,
            parent_id: hex::encode(pre.parent_id),
            height: pre.height,
            timestamp: pre.timestamp,
            n_bits: pre.n_bits,
            votes: pre.votes,
            miner_pubkey: hex::encode(pre.miner_pubkey),
        },
        pre_header_source: wire::SpendingPreHeaderSource::SyntheticCommittedTip,
        previous_state_digest: hex::encode(view.state_context().previous_state_digest.as_bytes()),
        parameters: wire::SpendingParameters {
            missing_core_parameters: p.missing_core_parameters,
            epoch_start_height: p.epoch_start_height,
            block_version: p.block_version,
            storage_fee_factor: p.storage_fee_factor,
            min_value_per_byte: p.min_value_per_byte,
            max_block_size: p.max_block_size,
            max_block_cost: p.max_block_cost,
            token_access_cost: p.token_access_cost,
            input_cost: p.input_cost,
            data_input_cost: p.data_input_cost,
            output_cost: p.output_cost,
            subblocks_per_block: p.subblocks_per_block,
            extra: p.extra.clone(),
            proposed_update: hex::encode(proposed_update),
            activated_update: hex::encode(activated_update),
            announced_settings: announced_settings.map(hex::encode),
        },
        validation_settings: hex::encode(adopted_settings),
        reemission,
        pruned: state.is_pruned(),
        minimum_history_height: Some(
            client
                .reader
                .minimal_full_block_height()
                .map_err(|e| InProcessChainClient::state_error("retained history height", e))?,
        ),
        min_relay_fee_nano_erg: provider.min_relay_fee_nano_erg,
        max_tx_size_bytes: u32::try_from(provider.max_tx_size_bytes).map_err(|_| {
            ChainClientError::Protocol("node transaction-size limit exceeds u32".into())
        })?,
        mempool_sequence: pool.publication_sequence,
        mempool_transactions: pool
            .pool_full_txs
            .iter()
            .map(|(_, bytes)| hex::encode(bytes.as_ref()))
            .collect(),
        private_mining_configured: pool.mining_enabled && provider.private_queue.is_some(),
        private_queue_revision,
        private_reserved_inputs,
    })
}

fn charge(bytes: &mut usize, amount: usize) -> Result<(), ChainClientError> {
    *bytes = bytes.saturating_add(amount);
    if *bytes > wire::MAX_SPENDING_CONTEXT_BYTES {
        return Err(ChainClientError::Unavailable(
            "spending context exceeds the 8 MiB wire budget; reduce the node pool before retrying"
                .into(),
        ));
    }
    Ok(())
}
