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
    ]);
    assert!(required.is_subset(&operations));
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

#[test]
fn canonical_scala_and_rust_operation_inventories_are_disjoint() {
    let scala = scala_openapi_operations();
    let rust = openapi_operations(&rust_openapi().expect("canonical RUST OpenAPI must merge"));
    assert_eq!(scala.len(), 125);
    assert_eq!(rust.len(), 179);

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
