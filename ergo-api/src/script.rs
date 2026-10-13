//! `/script/p2sAddress` + `/script/p2shAddress` — the two compile-requiring
//! members of Scala `ScriptApiRoute` (see `crate::utils` for the two
//! decode-only siblings, `addressToTree` / `addressToBytes`, which need no
//! compiler).
//!
//! **Public, ungated** — Scala's `ScriptApiRoute` carries no `withAuth`
//! (`ScriptApiRoute.scala:38-46`), so these two stay public here too.
//!
//! Scala folds the wallet's public keys into the compile env as
//! `myPubKey_N` (`keysToEnv`, `ScriptApiRoute.scala:52-54`). This node hosts no
//! wallet, so it compiles against an empty env: a script that references
//! `myPubKey_N` fails to compile with a `400`, like any other unknown name.
//!
//! State: a `(NetworkPrefix, ComputePool)` tuple; compilation runs on the
//! compute pool.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
use serde::Deserialize;
use serde_json::json;

use crate::utils::bad_request;

/// The 400 answer for a `source` above
/// [`crate::v1::script::MAX_SOURCE_LEN`], the same cap the native
/// `/api/v1/script/compile` applies. Checked before the wallet read and
/// before the compiler runs.
fn source_too_long(source: &str) -> Option<Response> {
    let cap = crate::v1::script::MAX_SOURCE_LEN;
    (source.len() > cap).then(|| bad_request(format!("Script source is limited to {cap} bytes")))
}

/// Wire request DTO — Scala `CompileRequest`
/// (`http/api/requests/CompileRequest.scala:10`: `case class
/// CompileRequest(source: String, treeVersion: Byte)`), decoded via
/// `Decoder.forProduct2("source", "treeVersion")`
/// (`ApiRequestsCodecs.scala:29`): the wire JSON is exactly `{"source":
/// "<script text>", "treeVersion": <byte>}`. `executeWithContext` is the ONE
/// `/script/*` member that also accepts a caller-supplied `namedConstants`
/// env — out of scope here, not one of these two routes.
#[derive(Deserialize)]
pub struct CompileRequestDto {
    source: String,
    #[serde(rename = "treeVersion")]
    tree_version: u8,
}

/// Compile `req.source` against an empty env and answer with one address
/// field, or a `bad_request` envelope on any compile failure. `pick` selects
/// which of `CompileResult`'s two pre-computed addresses to serve —
/// `p2s_address` for `p2sAddressR`, `p2sh_address` for `p2shAddressR`
/// (`ScriptApiRoute.scala:60-65`, `addressResponse`, `:50`).
async fn compile_address_response(
    network: NetworkPrefix,
    req: CompileRequestDto,
    compute: crate::v1::ComputePool,
    pick: fn(&ergo_compiler::CompileResult) -> &str,
) -> Response {
    if let Some(resp) = source_too_long(&req.source) {
        return resp;
    }
    compute
        .response(move || {
            match compile(&ScriptEnv::new(), &req.source, req.tree_version, network) {
                Ok(result) => Json(json!({ "address": pick(&result) })).into_response(),
                Err(e) => bad_request(e.to_string()),
            }
        })
        .await
}

/// `POST /script/p2sAddress` — Scala `p2sAddressR` (`ScriptApiRoute.scala:71-76`).
pub async fn p2s_address_handler(
    State((network, compute)): State<(NetworkPrefix, crate::v1::ComputePool)>,
    Json(req): Json<CompileRequestDto>,
) -> Response {
    compile_address_response(network, req, compute, |r| r.p2s_address.as_str()).await
}

/// `POST /script/p2shAddress` — Scala `p2shAddressR` (`ScriptApiRoute.scala:78-83`).
pub async fn p2sh_address_handler(
    State((network, compute)): State<(NetworkPrefix, crate::v1::ComputePool)>,
    Json(req): Json<CompileRequestDto>,
) -> Response {
    compile_address_response(network, req, compute, |r| r.p2sh_address.as_str()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::address::NetworkPrefix;

    // ----- error paths -----

    #[test]
    fn source_above_the_cap_is_rejected_and_at_the_cap_is_not() {
        let cap = crate::v1::script::MAX_SOURCE_LEN;
        assert!(source_too_long(&"a".repeat(cap)).is_none());
        let resp = source_too_long(&"a".repeat(cap + 1)).expect("over the cap");
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A flat chain of single-use `val`s is inlined into one nested
    /// expression, so its depth grows with the source length rather than
    /// with the parser's nesting. At the source cap, compiling it must end
    /// with a result or an error on the node's 8 MiB compute stack (a stack
    /// overflow would abort the test process).
    #[test]
    fn val_chain_at_the_source_cap_compiles_within_the_compute_stack() {
        let cap = crate::v1::script::MAX_SOURCE_LEN;
        let mut source = String::from("{ val a0 = HEIGHT\n");
        let mut n = 0usize;
        loop {
            let line = format!("val a{} = a{} + 1\n", n + 1, n);
            if source.len() + line.len() + 64 > cap {
                break;
            }
            source.push_str(&line);
            n += 1;
        }
        source.push_str(&format!("sigmaProp(a{n} > 0) }}"));
        assert!(source.len() <= cap && n > 2000, "chain length {n}");
        let handle = std::thread::Builder::new()
            .stack_size(ergo_ser::decode_stack::DECODE_THREAD_STACK_BYTES)
            .spawn(move || compile(&ScriptEnv::new(), &source, 0, NetworkPrefix::Mainnet).is_ok())
            .expect("spawn compile thread");
        // Either outcome is acceptable; reaching here means no overflow.
        let _compiled = handle.join().expect("compile thread did not panic");
    }
}
