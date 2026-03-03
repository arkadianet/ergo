use super::super::*;

/// `GET /emission/at/{height}` — emission info at block height.
#[utoipa::path(
    get,
    path = "/emission/at/{height}",
    tag = "emission",
    params(
        ("height" = u32, Path, description = "Block height")
    ),
    responses(
        (status = 200, description = "Emission info at height", body = Object)
    )
)]
pub(crate) async fn emission_handler(
    Path(height): Path<u32>,
) -> Json<ergo_network::emission::EmissionInfo> {
    Json(ergo_network::emission::emission_info(height))
}

/// `GET /emission/scripts` — emission contract addresses.
#[utoipa::path(
    get,
    path = "/emission/scripts",
    tag = "emission",
    responses(
        (status = 200, description = "Emission contract addresses", body = EmissionScriptsResponse)
    )
)]
pub(crate) async fn emission_scripts_handler(
    State(state): State<ApiState>,
) -> Json<EmissionScriptsResponse> {
    let network = network_prefix(&state.network);

    // Minimal placeholder ErgoTree bytes for emission contracts.
    // A fully accurate implementation would extract the real consensus-constant
    // ErgoTree bytes from the Scala reference.
    let emission_tree = [0xd1, 0x01];
    let reemission_tree = [0xd1, 0x02];
    let pay2reemission_tree = [0xd1, 0x03];

    Json(EmissionScriptsResponse {
        emission: address::ergo_tree_to_address(&emission_tree, network),
        reemission: address::ergo_tree_to_address(&reemission_tree, network),
        pay2_reemission: address::ergo_tree_to_address(&pay2reemission_tree, network),
    })
}
