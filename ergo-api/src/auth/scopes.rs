//! Explicit scope assignments for both authentication gates.

use super::CredentialScope;

/// Unknown operations deny every scoped key, including scoped administrators.
pub fn required_scope(method: &str, path: &str) -> Option<CredentialScope> {
    let method = if method == "HEAD" { "GET" } else { method };
    SCOPES.iter().find_map(|(verb, template, scope)| {
        (*verb == method && matches_path(template, path)).then_some(*scope)
    })
}

fn matches_path(template: &str, path: &str) -> bool {
    let normalize = |route: &str| {
        route
            .split('/')
            .map(|part| {
                if part.starts_with(':') || (part.starts_with('{') && part.ends_with('}')) {
                    "{}"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    normalize(template) == normalize(path)
}

const SCOPES: &[(&str, &str, CredentialScope)] = &[
    (
        "DELETE",
        "/api/v1/accounts/watch/{scan_id}",
        CredentialScope::Wallet,
    ),
    (
        "DELETE",
        "/api/v1/accounts/{account_id}",
        CredentialScope::Wallet,
    ),
    (
        "DELETE",
        "/api/v1/network/blacklist/{addr}",
        CredentialScope::Operator,
    ),
    (
        "DELETE",
        "/api/v1/network/peers/{addr}",
        CredentialScope::Operator,
    ),
    (
        "DELETE",
        "/api/v1/node/credentials/{id}",
        CredentialScope::Admin,
    ),
    (
        "DELETE",
        "/api/v1/scan/scans/{scan_id}",
        CredentialScope::Wallet,
    ),
    (
        "DELETE",
        "/api/v1/scan/scans/{scan_id}/boxes/{box_id}",
        CredentialScope::Wallet,
    ),
    (
        "DELETE",
        "/api/v1/webhooks/{webhook_id}",
        CredentialScope::Operator,
    ),
    ("GET", "/api/v1/accounts", CredentialScope::Wallet),
    (
        "GET",
        "/api/v1/accounts/{account_id}",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/accounts/{account_id}/addresses",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/accounts/{account_id}/balance",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/diagnostics/activity",
        CredentialScope::Operator,
    ),
    ("GET", "/api/v1/mining/candidate", CredentialScope::Mining),
    (
        "GET",
        "/api/v1/mining/candidate-details",
        CredentialScope::Mining,
    ),
    ("GET", "/api/v1/mining/history", CredentialScope::Mining),
    ("GET", "/api/v1/mining/policy", CredentialScope::Mining),
    (
        "GET",
        "/api/v1/mining/private-transactions",
        CredentialScope::Operator,
    ),
    (
        "GET",
        "/api/v1/mining/reward-address",
        CredentialScope::Mining,
    ),
    (
        "GET",
        "/api/v1/mining/reward-pubkey",
        CredentialScope::Mining,
    ),
    ("GET", "/api/v1/node/config", CredentialScope::Operator),
    ("GET", "/api/v1/node/credentials", CredentialScope::Admin),
    ("GET", "/api/v1/scan/scans", CredentialScope::Wallet),
    (
        "GET",
        "/api/v1/scan/scans/{scan_id}",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/scan/scans/{scan_id}/transactions",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/scan/scans/{scan_id}/unspent",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/transactions-psbt/{psbt_id}",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/voting/operator-votes",
        CredentialScope::Operator,
    ),
    ("GET", "/api/v1/wallet/addresses", CredentialScope::Wallet),
    ("GET", "/api/v1/wallet/balance", CredentialScope::Wallet),
    ("GET", "/api/v1/wallet/boxes", CredentialScope::Wallet),
    (
        "GET",
        "/api/v1/wallet/boxes/{boxId}",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/wallet/change-address",
        CredentialScope::Wallet,
    ),
    ("GET", "/api/v1/wallet/mining-jobs", CredentialScope::Wallet),
    ("GET", "/api/v1/wallet/status", CredentialScope::Wallet),
    (
        "GET",
        "/api/v1/wallet/transactions",
        CredentialScope::Wallet,
    ),
    (
        "GET",
        "/api/v1/wallet/transactions/{txId}",
        CredentialScope::Wallet,
    ),
    ("GET", "/api/v1/webhooks", CredentialScope::Operator),
    (
        "GET",
        "/api/v1/webhooks/{webhook_id}",
        CredentialScope::Operator,
    ),
    (
        "GET",
        "/api/v1/webhooks/{webhook_id}/deliveries",
        CredentialScope::Operator,
    ),
    ("GET", "/mining/candidate", CredentialScope::Mining),
    ("GET", "/mining/rewardAddress", CredentialScope::Mining),
    ("GET", "/mining/rewardPublicKey", CredentialScope::Mining),
    ("GET", "/scan/listAll", CredentialScope::Wallet),
    ("GET", "/scan/spentBoxes/{scanId}", CredentialScope::Wallet),
    (
        "GET",
        "/scan/unspentBoxes/{scanId}",
        CredentialScope::Wallet,
    ),
    ("GET", "/wallet/addresses", CredentialScope::Wallet),
    ("GET", "/wallet/balances", CredentialScope::Wallet),
    (
        "GET",
        "/wallet/balances/withUnconfirmed",
        CredentialScope::Wallet,
    ),
    ("GET", "/wallet/boxes", CredentialScope::Wallet),
    ("GET", "/wallet/boxes/unspent", CredentialScope::Wallet),
    ("GET", "/wallet/deriveNextKey", CredentialScope::Wallet),
    ("GET", "/wallet/lock", CredentialScope::Wallet),
    ("GET", "/wallet/status", CredentialScope::Wallet),
    ("GET", "/wallet/transactionById", CredentialScope::Wallet),
    ("GET", "/wallet/transactions", CredentialScope::Wallet),
    (
        "GET",
        "/wallet/transactionsByScanId/{scanId}",
        CredentialScope::Wallet,
    ),
    (
        "PATCH",
        "/api/v1/accounts/{account_id}",
        CredentialScope::Wallet,
    ),
    ("PATCH", "/api/v1/node/config", CredentialScope::Admin),
    (
        "PATCH",
        "/api/v1/webhooks/{webhook_id}",
        CredentialScope::Operator,
    ),
    ("POST", "/api/v1/accounts", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/accounts/private-key",
        CredentialScope::Admin,
    ),
    ("POST", "/api/v1/accounts/watch", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/accounts/{account_id}/addresses",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/mining/candidate-with-txs",
        CredentialScope::Mining,
    ),
    (
        "POST",
        "/api/v1/mining/private-transactions",
        CredentialScope::Operator,
    ),
    (
        "POST",
        "/api/v1/mining/private-transactions/{tx_id}/cancel",
        CredentialScope::Operator,
    ),
    ("POST", "/api/v1/mining/solution", CredentialScope::Mining),
    (
        "POST",
        "/api/v1/network/blacklist",
        CredentialScope::Operator,
    ),
    ("POST", "/api/v1/network/connect", CredentialScope::Operator),
    (
        "POST",
        "/api/v1/network/disconnect",
        CredentialScope::Operator,
    ),
    ("POST", "/api/v1/node/shutdown", CredentialScope::Admin),
    ("POST", "/api/v1/scan/scans", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/scan/scans/{scan_id}/boxes",
        CredentialScope::Wallet,
    ),
    ("POST", "/api/v1/script/compile", CredentialScope::Operator),
    ("POST", "/api/v1/script/cost", CredentialScope::Operator),
    ("POST", "/api/v1/script/diff", CredentialScope::Operator),
    ("POST", "/api/v1/script/execute", CredentialScope::Operator),
    ("POST", "/api/v1/script/explain", CredentialScope::Operator),
    ("POST", "/api/v1/script/inspect", CredentialScope::Operator),
    ("POST", "/api/v1/script/simulate", CredentialScope::Operator),
    ("POST", "/api/v1/transactions-psbt", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/transactions-psbt/{psbt_id}/contributions",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/transactions-psbt/{psbt_id}/finalize",
        CredentialScope::Wallet,
    ),
    ("POST", "/api/v1/votes", CredentialScope::Operator),
    (
        "POST",
        "/api/v1/voting/operator-votes",
        CredentialScope::Operator,
    ),
    ("POST", "/api/v1/wallet/addresses", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/wallet/boxes/select",
        CredentialScope::Wallet,
    ),
    ("POST", "/api/v1/wallet/init", CredentialScope::Wallet),
    ("POST", "/api/v1/wallet/lock", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/wallet/mining-jobs",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/wallet/mining-jobs/{job_id}/cancel",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/wallet/mnemonic/verify",
        CredentialScope::Wallet,
    ),
    ("POST", "/api/v1/wallet/rescan", CredentialScope::Wallet),
    ("POST", "/api/v1/wallet/restore", CredentialScope::Wallet),
    (
        "POST",
        "/api/v1/wallet/rewards/retrieve",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/wallet/transactions/build",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/wallet/transactions/send",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/api/v1/wallet/transactions/sign",
        CredentialScope::Wallet,
    ),
    ("POST", "/api/v1/wallet/unlock", CredentialScope::Wallet),
    ("POST", "/api/v1/webhooks", CredentialScope::Operator),
    ("POST", "/blocks", CredentialScope::Operator),
    ("POST", "/mining/candidateWithTxs", CredentialScope::Mining),
    (
        "POST",
        "/mining/candidateWithTxsAndPk",
        CredentialScope::Mining,
    ),
    ("POST", "/mining/solution", CredentialScope::Mining),
    ("POST", "/node/shutdown", CredentialScope::Admin),
    ("POST", "/peers/connect", CredentialScope::Operator),
    ("POST", "/scan/addBox", CredentialScope::Wallet),
    ("POST", "/scan/deregister", CredentialScope::Wallet),
    ("POST", "/scan/p2sRule", CredentialScope::Wallet),
    ("POST", "/scan/register", CredentialScope::Wallet),
    ("POST", "/scan/stopTracking", CredentialScope::Wallet),
    ("POST", "/wallet/boxes/collect", CredentialScope::Wallet),
    ("POST", "/wallet/check", CredentialScope::Wallet),
    ("POST", "/wallet/deriveKey", CredentialScope::Wallet),
    ("POST", "/wallet/extractHints", CredentialScope::Wallet),
    (
        "POST",
        "/wallet/generateCommitments",
        CredentialScope::Wallet,
    ),
    ("POST", "/wallet/getPrivateKey", CredentialScope::Admin),
    ("POST", "/wallet/init", CredentialScope::Wallet),
    ("POST", "/wallet/payment/send", CredentialScope::Wallet),
    ("POST", "/wallet/rescan", CredentialScope::Wallet),
    ("POST", "/wallet/restore", CredentialScope::Wallet),
    (
        "POST",
        "/wallet/transaction/generate",
        CredentialScope::Wallet,
    ),
    (
        "POST",
        "/wallet/transaction/generateUnsigned",
        CredentialScope::Wallet,
    ),
    ("POST", "/wallet/transaction/send", CredentialScope::Wallet),
    ("POST", "/wallet/transaction/sign", CredentialScope::Wallet),
    ("POST", "/wallet/unlock", CredentialScope::Wallet),
    (
        "POST",
        "/wallet/updateChangeAddress",
        CredentialScope::Wallet,
    ),
    ("PUT", "/api/v1/mining/policy", CredentialScope::Operator),
    (
        "PUT",
        "/api/v1/wallet/change-address",
        CredentialScope::Wallet,
    ),
];
