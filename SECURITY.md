# Security Policy

## Status

Pre-1.0. The codebase is alpha — consensus-critical code paths are
oracle-tested against the Scala reference node and against mainnet, but
the node has not yet had broad real-world deployment exposure. This is an
independent reimplementation, **not** the Scala reference client; it
targets strict consensus compatibility by design but is not the canonical
node (scope: [docs/compatibility.md](./docs/compatibility.md)). **Do not
rely on this node for funds custody or production infrastructure, and
verify its verdicts against the Scala reference node before trusting
them.** Treat disclosed issues as load-bearing.

## Supported versions

Pre-1.0 software receives security fixes on the latest released tag only.
There are no long-term-support branches before 1.0, and a pre-1.0 fix may
ship in a release that also contains breaking changes.

| Version | Supported |
|---|---|
| Latest released tag | Yes — security fixes land here |
| Any older tag | No — upgrade to the latest tag |
| `main` / unreleased | Best-effort; report against the commit hash |

Releases are published at
<https://github.com/arkadianet/ergo/releases>. Always state the
exact tag or commit hash you reproduced against when reporting.

## Scope

In scope for security disclosure:

- **Consensus**: any input that causes this node to accept a block the
  Scala reference rejects, or reject a block the Scala reference accepts.
- **State integrity**: any input that causes UTXO-state divergence,
  AVL+ digest divergence, or undo-log corruption that survives a clean
  shutdown.
- **Crash / DoS via remote input**: any peer message, gossip payload, or
  REST request that crashes the node or pins it in an unrecoverable
  loop.
- **Crypto**: any case where a cryptographic check (signature, PoW,
  Merkle proof, AVL+ proof) returns the wrong verdict.

Out of scope:

- Issues only reproducible against a self-built fork that has changed
  consensus-critical files.
- Findings against `sigma-rust` directly (report upstream); it is used
  only as a dev/test oracle, never as runtime consensus logic.
- Performance regressions that do not affect correctness.
- The deliberately-unauthenticated REST surface when the node is exposed
  beyond loopback without a proxy (see Security posture below) — that is
  a documented operator-configuration trade-off, not a node defect.

## Security posture

This section describes the security model the node ships with so operators
can deploy it safely. It is grounded in the current code; the authoritative
configuration reference is the README and `ergo-node/ergo-node.toml`.

### API bind defaults to loopback

When enabled, the REST API binds to `127.0.0.1:9099` by default. A
non-loopback `[api] bind` is **rejected at config load** unless `[api]
public_bind = true` is also set — the node refuses to start and prints
why. Loopback binds (`127.0.0.1`, `[::1]`) need no flag.

The loader default is loopback; the shipped ready-to-use
`ergo-node/ergo-node.toml` and example both enable the API without a
credential. Dashboard, swagger and public REST work immediately. Privileged
routes stay closed until an operator configures `[api.security] api_key_hash`.
Operators upgrading the bundled file directly lose its old `hello` key;
privileged calls with that key fail until they configure their own hash.

```toml
[api]
# Default. Reachable only from the same host.
bind = "127.0.0.1:9099"

# To bind a routable interface you must opt in explicitly, and accept
# that the unauthenticated routes below become world-callable.
# bind = "0.0.0.0:9099"
# public_bind = true
```

For remote operator access, the recommended deployment is to keep the
bind on loopback and front it with an authenticated reverse proxy, rather
than setting `public_bind = true`.

### Privileged routes fail closed

Authentication uses the `api_key` HTTP header and a constant-time comparison
with the configured lowercase Base16 `Blake2b256(secret)` hash. A missing or
wrong client key retains the Scala-compatible `403 invalid.api-key` response.
With no configured hash, privileged routes return a distinct
`403 api-key-not-configured` and setup guidance. The v1 tier gate uses its
`401 unauthorized` envelope with the same guidance. Loopback does not bypass
either gate.

The API distinguishes public routes from privileged routes:

| Privileged (require a configured hash and valid `api_key`) | Public (no key required) |
|---|---|
| `/wallet/*`, `/scan/*`, `/api/v1/wallet/*` | Dashboard `/`, `/wallet/ui*` redirects, swagger |
| `POST /node/shutdown`, `POST /api/v1/node/shutdown`, `POST /peers/connect`, `POST /api/v1/votes`, `POST /blocks` | Read REST, including `GET /api/v1/votes`, `/info`, `/blocks/*`, `/peers/*`, `/blockchain/*` |
| `/mining/*` (candidate, solution, reward address/public key) | Transaction submission/checks: `POST /transactions`, `/transactions/bytes`, `/transactions/check`, `/transactions/checkBytes`, `/api/v1/mempool/{submit,check}` |
| v1 Operator/Admin routes (node config, network controls, mining controls, operator votes, scans, account management/PSBT, watch writes, private-key export, webhooks); script compute when configured to require a key | Public v1 queries including watch-only account reads, `/emission/*`, `/utils/*`, `/metrics` |

The whole wallet, scan and node prefixes are gated, including unknown subpaths
(the node answers its wallet and scan prefixes with `410 wallet_moved`);
other unmatched paths return `404`. Public means no API-key authentication;
normal validation, subsystem availability and admission policies still apply.

Transaction submission is public in Scala (`TransactionsApiRoute.scala:174-209`).
Block submission requires an API key, matching Scala (`BlocksApiRoute.scala:127`). This node gates all four mining routes above;
Scala leaves those four open (`MiningApiRoute.scala:45,77,86,98`).


Use [the configuration guide](docs/configuration.md#security-notes-for-the-api) to
generate a random secret; set its hash under `[api.security]` and restart.
Neither template ships a key.

`local_reverse_proxy = true` withdraws loopback trust for rate limits, Admin
posture and transaction budgets. It does **not** authenticate clients or unlock
privileged routes. Configure authentication and per-client limits at the proxy.
The Host guard remains active on loopback: a DNS-rebinding browser can send an
`api_key` header under its same-origin hostname, so header spelling alone is no
defense. Keep the Host allowlist narrow and use a secret key.

On a routable interface, `public_bind = true` makes public reads, transaction
submission, and metrics network-callable. Keep `/metrics` on
loopback or behind an authenticated proxy.

### The wallet runs in its own daemon; the node holds no keys

The node hosts no wallet: it never opens wallet secrets, runs no wallet
writer, and answers its former `/wallet/*`, `/scan/*` and `/api/v1/wallet/*`
routes (after the API-key check) with `410 wallet_moved` and the configured
`[wallet] daemon_address`. The wallet is `ergo-walletd`, a separate process
with its own data directory and `wallet.redb`. It starts watch-only (public
descriptors, read API) unless seed mode is configured; only seed mode holds
an encrypted seed and can sign.

- **Sealed and locked by default.** The daemon encrypts `wallet.redb`
  (AES-256-GCM) and starts sealed: the database opens only when the wallet
  password, a passphrase or an `unseal_key_file` releases it. Seed wallets
  restart locked and lock again after `[security] idle_lock` or `max_unlock`.
  Unlock attempts are budgeted and the budget survives restarts.
- **Local, authenticated API.** The daemon listens on a Unix socket
  (mode `0600`) or a loopback TCP address, with a Host-header guard, and every
  route needs its own API credential (a file readable only by its owner). It
  disables core dumps and ptrace before reading any credential.
- **The browser holds no keys.** The wallet UI is a static page served by the
  daemon. Derivation and signing happen in the daemon; the page keeps only the
  daemon API key in `sessionStorage`. The password and recovery mnemonic exist
  in page memory only during init and recovery, and the mnemonic is visible on
  screen while it is displayed.
- **Chain data is verified.** The daemon checks header proof of work and
  that each block's transactions match its header, and authenticates box ids,
  but trusts the node it is pointed at for chain selection and difficulty.
- **Private-key export is off.** The daemon runs its engine with
  `expose_private_keys = false` and has no setting that turns it on, so
  `getPrivateKey` is refused.
- **Multisig nonces stay in the daemon by default.** A Schnorr signature
  made with a nonce someone else knows, or with one nonce for two messages,
  reveals the signing key. So `generateCommitments` returns a single-use
  handle, bound to its input and public commitment, in place of each secret
  nonce, and signing refuses a caller-supplied nonce for a key the wallet
  holds. This is also the default of the wallet engine itself; handing nonces
  to the caller is an explicit opt-in, `[security] multisig_nonces = "caller"`
  in the daemon, which restores the Scala form for old clients and logs a
  warning at start. Handles live only in memory, expire after an hour and are
  wiped when the wallet locks.

See [wallet setup](docs/wallet-setup.md) and
[wallet extraction](docs/wallet-extraction.md).

### This is pre-stable software that can move funds

The wallet can hold keys and broadcast spends, and the node validates
consensus state that real funds depend on, but the software is pre-1.0
alpha with limited deployment exposure. Run it against funds you can
afford to lose, on a host you control, behind
loopback or an authenticated proxy — and cross-check anything
consensus-critical against the Scala reference node.

## Reporting a vulnerability

Please report privately, before any public disclosure or PR.

- **Preferred:** open a private report through GitHub's
  [Report a vulnerability](https://github.com/arkadianet/ergo/security/advisories/new)
  flow on the repository's **Security** tab. The advisory draft is visible
  only to the maintainers, who respond there. This uses GitHub's private
  vulnerability reporting — no email address is exposed.
- Title: `ergo security: <one-line summary>`.
- Include: affected version (tag or commit hash), reproduction steps,
  expected vs observed behavior, and your suggested severity. A PoC or
  failing test case is appreciated.

If the issue is consensus-critical, please **also** flag whether you have
shared the same finding with the Scala reference team — coordinated
disclosure across both implementations is the right path for any bug that
could split the network.

## Response

- Acknowledgement within **3 business days**.
- Initial assessment + severity within **7 business days**.
- For consensus-critical issues, target a coordinated patch within
  **30 days**.
- For lower-severity issues, target a fix within **90 days**.

We will credit reporters in the release notes unless they ask to remain
anonymous.

## Out-of-band patches

Critical-severity fixes ship as a tagged patch release with a release
note and a CHANGELOG entry. Operators should subscribe to both channels
to be notified of patch availability:

- Releases: <https://github.com/arkadianet/ergo/releases>
- Security Advisories: <https://github.com/arkadianet/ergo/security/advisories>
