use std::borrow::Cow;
use std::sync::OnceLock;

use utoipa::openapi::{schema::Schema, RefOr};
use utoipa::{PartialSchema, ToSchema};

const NATIVE_SCHEMA_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/openapi_native.yaml"
));

static DOCUMENT: OnceLock<serde_norway::Value> = OnceLock::new();

fn native_schema(name: &str) -> RefOr<Schema> {
    let document = DOCUMENT.get_or_init(|| {
        serde_norway::from_str(NATIVE_SCHEMA_FIXTURE).expect("native OpenAPI fixture must parse")
    });
    let value = document["components"]["schemas"][name].clone();
    if value.is_null() {
        panic!("native OpenAPI schema is missing: {name}");
    }
    serde_norway::from_value(value).expect("native OpenAPI schema must deserialize")
}

fn add_native_schema(name: &str, schemas: &mut Vec<(String, RefOr<Schema>)>) {
    if schemas.iter().any(|(existing, _)| existing == name) {
        return;
    }
    schemas.push((name.to_string(), native_schema(name)));
}

macro_rules! native_schema_markers {
    ($($name:ident),* $(,)?) => {
        $(
            pub(crate) struct $name;

            impl PartialSchema for $name {
                fn schema() -> RefOr<Schema> {
                    native_schema(stringify!($name))
                }
            }

            impl ToSchema for $name {
                fn name() -> Cow<'static, str> {
                    Cow::Borrowed(stringify!($name))
                }

                fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
                    add_native_schema(stringify!($name), schemas);
                }
            }
        )*
    };
}

native_schema_markers!(
    WalletBalanceDto,
    NanoErgBreakdownDto,
    ReemissionInfoDto,
    UnconfirmedDeltaDto,
    ScopeDto,
    WalletAssetDto,
    WalletStatusDto,
    NetworkDto,
    RescanStateDto,
    WalletAddressDto,
    AddressPage,
    WalletBoxSummary,
    BoxStatusDto,
    BoxProvenanceDto,
    BoxPage,
    WalletTransactionSummary,
    TxPage,
    UnlockRequest,
    MnemonicVerifyRequest,
    MnemonicVerifyResult,
    InitRequest,
    InitResponse,
    RestoreRequest,
    DerivationMode,
    DeriveKeyRequest,
    DerivedAddress,
    ChangeAddressDto,
    SetChangeAddressRequest,
    RescanRequest,
    TxRepr,
    OutputIntent,
    InputSource,
    DataInputSource,
    TxIntent,
    SelectTarget,
    BoxSelectRequest,
    SelectedBoxRef,
    ChangePlan,
    ReemissionBurn,
    BoxSelectResponse,
    BuildTxResponse,
    ExternalSecret,
    SignTxRequest,
    SignTxResponse,
    SendTxRequest,
    SendTxResponse,
    RetrieveRewardsRequest,
    RetrieveRewardsResultDto,
    SweptTokenDto,
    NativeWalletError,
);
