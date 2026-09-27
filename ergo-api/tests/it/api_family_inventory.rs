use std::collections::BTreeSet;

use ergo_api::api_family::{ApiFamily, API_FAMILIES};
use ergo_api::server::{
    legacy_rust_openapi, merge_openapi_checked, openapi_operations, rust_openapi,
    scala_openapi_operations, v1_openapi_fragment, OpenApiMergeError, RouteOperation,
};
use utoipa::openapi::{
    path::{HttpMethod, Operation},
    schema::ObjectBuilder,
    ComponentsBuilder, Info, OpenApi, OpenApiBuilder, PathItem, PathsBuilder,
};

fn canonical_json() -> serde_json::Value {
    serde_json::to_value(rust_openapi().expect("canonical RUST OpenAPI")).unwrap()
}

fn get_operation<'a>(
    document: &'a serde_json::Value,
    path: &str,
    method: &str,
) -> &'a serde_json::Value {
    &document["paths"][path][method]
}

fn parameter<'a>(operation: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["name"] == name)
        .unwrap_or_else(|| panic!("missing parameter {name}"))
}

fn response_schema_ref<'a>(operation: &'a serde_json::Value, status: &str) -> &'a str {
    operation["responses"][status]["content"]["application/json"]["schema"]["$ref"]
        .as_str()
        .unwrap_or_else(|| panic!("missing response schema for status {status}"))
}

fn response_statuses(operation: &serde_json::Value) -> BTreeSet<&str> {
    operation["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn operation(path: &str, method: &str) -> RouteOperation {
    RouteOperation::new(path, method)
}

fn one_operation_doc(path: &str, method: HttpMethod) -> OpenApi {
    OpenApi::new(
        Info::new("test", "1"),
        PathsBuilder::new()
            .path(path, PathItem::new(method, Operation::new()))
            .build(),
    )
}

fn component_doc(schema_type: utoipa::openapi::schema::Type) -> OpenApi {
    OpenApiBuilder::new()
        .info(Info::new("test", "1"))
        .paths(PathsBuilder::new().build())
        .components(Some(
            ComponentsBuilder::new()
                .schema("Shared", ObjectBuilder::new().schema_type(schema_type))
                .build(),
        ))
        .build()
}

#[test]
fn public_api_family_model_has_exactly_two_families() {
    assert_eq!(API_FAMILIES.len(), 2);
    assert_eq!(API_FAMILIES[0].family, ApiFamily::Scala);
    assert_eq!(API_FAMILIES[0].label, "Scala API");
    assert_eq!(API_FAMILIES[0].swagger_url, "/swagger");
    assert_eq!(API_FAMILIES[0].openapi_url, "/api-docs/openapi-scala.yaml");
    assert_eq!(API_FAMILIES[1].family, ApiFamily::Rust);
    assert_eq!(API_FAMILIES[1].label, "RUST API");
    assert_eq!(API_FAMILIES[1].swagger_url, "/swagger/native");
    assert_eq!(API_FAMILIES[1].openapi_url, "/api-docs/openapi-rust.yaml");
}

#[test]
fn checked_openapi_merge_rejects_path_method_collisions() {
    let mut base = one_operation_doc("/collision", HttpMethod::Get);
    let incoming = one_operation_doc("/collision", HttpMethod::Get);

    assert!(matches!(
        merge_openapi_checked(&mut base, incoming),
        Err(OpenApiMergeError::PathMethodCollision { .. })
    ));
}

#[test]
fn checked_openapi_merge_accepts_only_structurally_equal_duplicate_components() {
    let mut equal = component_doc(utoipa::openapi::schema::Type::Object);
    merge_openapi_checked(
        &mut equal,
        component_doc(utoipa::openapi::schema::Type::Object),
    )
    .expect("equal duplicate schemas are safe");

    let mut unequal = component_doc(utoipa::openapi::schema::Type::Object);
    assert!(matches!(
        merge_openapi_checked(
            &mut unequal,
            component_doc(utoipa::openapi::schema::Type::String)
        ),
        Err(OpenApiMergeError::ComponentConflict { .. })
    ));
}

#[test]
fn canonical_rust_openapi_is_the_union_of_both_fragments_and_known_aliases() {
    let canonical = rust_openapi().expect("canonical RUST OpenAPI must merge");
    let operations = openapi_operations(&canonical);
    let legacy = openapi_operations(&legacy_rust_openapi());
    let v1 = openapi_operations(&v1_openapi_fragment());

    assert!(legacy.is_subset(&operations));
    assert!(v1.is_subset(&operations));

    let required = BTreeSet::from([
        operation("/api/v1/transactions/{txId}/detail", "get"),
        operation("/blockchain/storageRent/eligibleAt/{height}", "get"),
        operation("/blockchain/storageRent/maturesAt/{height}", "get"),
        operation("/blockchain/storageRent/maturesInRange", "get"),
        operation("/api/v1/mempool/submit", "post"),
        operation("/api/v1/mempool/check", "post"),
        operation("/api/v1/addresses/{address}/boxes", "get"),
        operation("/api/v1/addresses/{address}/unspent", "get"),
        operation("/api/v1/accounts", "get"),
        operation("/api/v1/accounts", "post"),
        operation("/api/v1/accounts/{account_id}", "patch"),
        operation("/api/v1/accounts/{account_id}", "delete"),
        operation("/api/v1/transactions-psbt/{psbt_id}", "get"),
        operation("/api/v1/transactions-psbt/{psbt_id}/contributions", "post"),
        operation("/api/v1/transactions-psbt/{psbt_id}/finalize", "post"),
        operation("/api/v1/chain/tip", "get"),
        operation("/api/v1/chain/snapshot", "get"),
        operation("/api/v1/chain/boxes/{id}", "get"),
        operation("/api/v1/chain/blocks-since", "get"),
        operation("/api/v1/chain/transactions", "post"),
    ]);
    assert!(required.is_subset(&operations));
}

#[test]
fn wallet_chain_operations_have_unique_ids_and_runtime_error_schemas() {
    let document = canonical_json();
    let operations = [
        ("/api/v1/chain/tip", "get", "wallet_chain_tip"),
        ("/api/v1/chain/snapshot", "get", "wallet_chain_snapshot"),
        ("/api/v1/chain/boxes/{id}", "get", "wallet_chain_box_lookup"),
        (
            "/api/v1/chain/blocks-since",
            "get",
            "wallet_chain_blocks_since",
        ),
        ("/api/v1/chain/transactions", "post", "wallet_chain_submit"),
    ];
    let expected_ids = operations
        .iter()
        .map(|(_, _, operation_id)| *operation_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_ids.len(), operations.len());

    let all_operation_ids = document["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|path| path.as_object().unwrap().values())
        .filter_map(|operation| operation["operationId"].as_str())
        .collect::<Vec<_>>();
    for (path, method, operation_id) in operations {
        assert_eq!(
            get_operation(&document, path, method)["operationId"],
            operation_id
        );
        assert_eq!(
            all_operation_ids
                .iter()
                .filter(|candidate| **candidate == operation_id)
                .count(),
            1,
            "{operation_id} must be globally unique"
        );
    }

    let submit = get_operation(&document, "/api/v1/chain/transactions", "post");
    assert_eq!(
        response_statuses(submit),
        BTreeSet::from(["200", "400", "409", "500", "503", "504"])
    );
    assert_eq!(
        response_schema_ref(submit, "400"),
        "#/components/schemas/WalletChainSubmitBadRequest"
    );
    let bad_request_refs = document["components"]["schemas"]["WalletChainSubmitBadRequest"]
        ["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|schema| schema["$ref"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        bad_request_refs,
        BTreeSet::from([
            "#/components/schemas/V1Error",
            "#/components/schemas/WalletChainSubmitResponse",
        ])
    );

    let blocks_since = get_operation(&document, "/api/v1/chain/blocks-since", "get");
    assert_eq!(
        response_schema_ref(blocks_since, "410"),
        "#/components/schemas/WalletChainPrunedBlocksSinceResponse"
    );

    let reemission = &document["components"]["schemas"]["WalletChainReemissionInput"];
    let required = reemission["required"].as_array().unwrap();
    assert!(!required.iter().any(|field| field == "boxIds"));
    assert!(reemission["properties"]["boxIds"].is_object());
}

#[test]
fn canonical_rust_openapi_preserves_prices_contract() {
    let document = canonical_json();
    let operations = openapi_operations(&rust_openapi().expect("canonical RUST OpenAPI"));
    assert_eq!(
        operations
            .iter()
            .filter(|operation| operation.path == "/api/v1/prices" && operation.method == "get")
            .count(),
        1
    );

    let operation = get_operation(&document, "/api/v1/prices", "get");
    assert_eq!(operation["tags"], serde_json::json!(["prices"]));

    let token_id = parameter(operation, "token_id");
    assert_eq!(token_id["in"], "query");
    assert_eq!(token_id["required"], true);
    assert_eq!(token_id["schema"]["type"], "string");

    let quote = parameter(operation, "quote");
    assert_eq!(quote["in"], "query");
    assert!(!quote["required"].as_bool().unwrap_or(false));
    assert_eq!(quote["schema"]["type"], "string");

    assert_eq!(
        response_statuses(operation),
        BTreeSet::from(["200", "400", "409", "500", "503"])
    );
    assert_eq!(
        response_schema_ref(operation, "200"),
        "#/components/schemas/PricesResponse"
    );
    for status in ["400", "409", "500", "503"] {
        assert_eq!(
            response_schema_ref(operation, status),
            "#/components/schemas/V1Error"
        );
    }

    let schemas = &document["components"]["schemas"];
    for schema in [
        "PriceItem",
        "PricePathHop",
        "PriceSource",
        "PriceValue",
        "PricesQuery",
        "PricesResponse",
        "RawPrice",
    ] {
        assert!(
            schemas[schema].is_object(),
            "missing prices schema {schema}"
        );
    }
}

#[test]
fn supplemental_seam_operations_are_method_specific() {
    let document = canonical_json();
    for (path, method, operation_id, summary) in [
        (
            "/api/v1/accounts",
            "post",
            "accounts_create",
            "Create named account (unavailable)",
        ),
        (
            "/api/v1/accounts/{account_id}",
            "patch",
            "account_patch",
            "Update named account (unavailable)",
        ),
        (
            "/api/v1/accounts/{account_id}",
            "delete",
            "account_delete",
            "Delete named account (unavailable)",
        ),
        (
            "/api/v1/transactions-psbt/{psbt_id}",
            "get",
            "psbt_get",
            "Get PSBT session (unavailable)",
        ),
    ] {
        let operation = get_operation(&document, path, method);
        assert_eq!(operation["operationId"], operation_id);
        assert_eq!(operation["summary"], summary);
        assert!(
            operation.get("requestBody").is_none(),
            "{method} {path} does not consume a request body while unavailable"
        );
        assert_eq!(
            response_statuses(operation),
            BTreeSet::from(["503"]),
            "{method} {path} must document the seam's actual response"
        );
        assert_eq!(
            response_schema_ref(operation, "503"),
            "#/components/schemas/V1Error"
        );
    }
}

#[test]
fn canonical_rust_openapi_preserves_transaction_detail_contract() {
    let document = canonical_json();
    let operation = get_operation(&document, "/api/v1/transactions/{txId}/detail", "get");
    let tx_id = parameter(operation, "txId");
    assert_eq!(tx_id["in"], "path");
    assert_eq!(tx_id["required"], true);
    assert_eq!(tx_id["schema"]["type"], "string");
    assert_eq!(
        response_statuses(operation),
        BTreeSet::from(["200", "404", "default"])
    );
    assert_eq!(
        response_schema_ref(operation, "200"),
        "#/components/schemas/ApiTxDetail"
    );
    assert_eq!(
        response_schema_ref(operation, "404"),
        "#/components/schemas/ApiError"
    );
    assert_eq!(
        response_schema_ref(operation, "default"),
        "#/components/schemas/ApiError"
    );
    assert!(document["components"]["schemas"]["ApiTxDetail"].is_object());
    assert!(document["components"]["schemas"]["ApiIoBox"].is_object());
    assert!(document["components"]["schemas"]["ApiAsset"].is_object());
}

fn assert_storage_paging_contract(operation: &serde_json::Value) {
    let offset = parameter(operation, "offset");
    assert_eq!(offset["schema"]["minimum"], 0);
    assert_eq!(offset["schema"]["default"], 0);

    let limit = parameter(operation, "limit");
    assert_eq!(limit["schema"]["minimum"], 1);
    assert_eq!(limit["schema"]["maximum"], 16_384);
    assert_eq!(limit["schema"]["default"], 100);

    let sort = parameter(operation, "sortDirection");
    assert_eq!(sort["schema"]["enum"], serde_json::json!(["asc", "desc"]));
    assert_eq!(sort["schema"]["default"], "desc");
}

fn assert_storage_responses(operation: &serde_json::Value, has_bad_request: bool) {
    let expected = if has_bad_request {
        BTreeSet::from(["200", "400", "503", "default"])
    } else {
        BTreeSet::from(["200", "503", "default"])
    };
    assert_eq!(response_statuses(operation), expected);
    assert_eq!(
        response_schema_ref(operation, "200"),
        "#/components/schemas/StorageRentEligibleResponse"
    );
    if has_bad_request {
        assert_eq!(
            response_schema_ref(operation, "400"),
            "#/components/schemas/ApiError"
        );
    }
    assert_eq!(
        response_schema_ref(operation, "503"),
        "#/components/schemas/ApiError"
    );
    assert_eq!(
        response_schema_ref(operation, "default"),
        "#/components/schemas/ApiError"
    );
}

#[test]
fn canonical_rust_openapi_preserves_all_storage_rent_contracts() {
    let document = canonical_json();
    let eligible = get_operation(
        &document,
        "/blockchain/storageRent/eligibleAt/{height}",
        "get",
    );
    let eligible_height = parameter(eligible, "height");
    assert_eq!(eligible_height["required"], true);
    assert_eq!(eligible_height["schema"]["minimum"], 0);
    assert_storage_paging_contract(eligible);
    assert_storage_responses(eligible, false);

    let matures_at = get_operation(
        &document,
        "/blockchain/storageRent/maturesAt/{height}",
        "get",
    );
    assert_eq!(parameter(matures_at, "height")["schema"]["minimum"], 0);
    assert_storage_paging_contract(matures_at);
    assert_storage_responses(matures_at, false);

    let range = get_operation(&document, "/blockchain/storageRent/maturesInRange", "get");
    for name in ["fromHeight", "toHeight"] {
        let bound = parameter(range, name);
        assert_eq!(bound["required"], true);
        assert_eq!(bound["schema"]["minimum"], 0);
    }
    assert_storage_paging_contract(range);
    assert_storage_responses(range, true);

    let schemas = &document["components"]["schemas"];
    assert!(schemas["StorageRentEligibleResponse"].is_object());
    assert!(schemas["StorageRentEligibleEntry"].is_object());
    assert_eq!(
        schemas["StorageRentEligibleEntry"]["properties"]["expectedConsensusBranch"]["enum"],
        serde_json::json!(["wholeBoxTake", "recreateWithFee", "overflowInverted"])
    );
    assert!(schemas["Asset"].is_object());
    assert!(schemas["ApiError"].is_object());
}

fn operation_inventory_text(operations: &BTreeSet<RouteOperation>) -> String {
    let mut text = operations
        .iter()
        .map(|op| format!("{} {}", op.method, op.path))
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text
}

fn load_operation_inventory_fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "could not read inventory fixture {path}: {error}\n\
             Generate it with:\n  \
             cargo test -p ergo-api --test api_family_inventory regenerate_operation_inventories -- --ignored --nocapture"
        )
    })
}

fn assert_operation_inventory_matches_fixture(
    operations: &BTreeSet<RouteOperation>,
    fixture_name: &str,
) {
    let actual = operation_inventory_text(operations);
    let expected = load_operation_inventory_fixture(fixture_name);
    assert_eq!(
        actual, expected,
        "{fixture_name} drifted from the checked-in (path, method) inventory.\n\
         If this change is intentional, regenerate the fixture:\n  \
         cargo test -p ergo-api --test api_family_inventory regenerate_operation_inventories -- --ignored --nocapture"
    );
}

#[test]
fn canonical_scala_and_rust_operation_inventories_are_disjoint() {
    let scala = scala_openapi_operations();
    let rust = openapi_operations(&rust_openapi().expect("canonical RUST OpenAPI must merge"));
    assert_eq!(scala.len(), 125);
    assert_eq!(rust.len(), 185);
    assert_operation_inventory_matches_fixture(&scala, "api_family_scala_operations.txt");
    assert_operation_inventory_matches_fixture(&rust, "api_family_rust_operations.txt");

    let overlap: Vec<_> = scala.intersection(&rust).collect();
    assert!(
        overlap.is_empty(),
        "family inventories overlap: {overlap:?}"
    );
    assert!(!scala.iter().any(|op| op.path.starts_with("/api/v1/")));
    assert!(!scala
        .iter()
        .any(|op| op.path.starts_with("/blockchain/storageRent/")));
    for unmounted in [
        "/transactions/unconfirmed/inputs/byBoxId/{boxId}",
        "/transactions/unconfirmed/outputs/byBoxId/{boxId}",
        "/transactions/unconfirmed/outputs/byErgoTree",
        "/transactions/unconfirmed/outputs/byTokenId/{tokenId}",
        "/transactions/unconfirmed/outputs/byRegisters",
        "/mining/candidateWithTxs",
        "/utxo/getBoxesBinaryProof",
        "/script/executeWithContext",
    ] {
        assert!(!scala.iter().any(|op| op.path == unmounted));
    }
}

/// Rewrites the checked-in family inventory fixtures from the current OpenAPI
/// documents. Ignored by default so a normal `cargo test` never mutates them.
#[test]
#[ignore = "writes golden inventory fixtures; run explicitly after an intentional inventory change"]
fn regenerate_operation_inventories() {
    let fixtures = [
        (
            "api_family_scala_operations.txt",
            scala_openapi_operations(),
        ),
        (
            "api_family_rust_operations.txt",
            openapi_operations(&rust_openapi().expect("canonical RUST OpenAPI must merge")),
        ),
    ];
    for (name, operations) in fixtures {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let text = operation_inventory_text(&operations);
        std::fs::write(&path, &text)
            .unwrap_or_else(|error| panic!("could not write inventory fixture {path}: {error}"));
        eprintln!(
            "regenerated {path} ({} operations, {} bytes)",
            operations.len(),
            text.len()
        );
    }
}
