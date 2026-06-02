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
| `master` / unreleased | Best-effort; report against the commit hash |

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

The REST API binds to `127.0.0.1:9099` by default. A non-loopback `[api]
bind` is **rejected at config load** unless `[api] public_bind = true` is
also set — the node refuses to start and prints why. Loopback binds
(`127.0.0.1`, `[::1]`) need no flag.

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

### `api_key` gates `/wallet/*` and `/node/shutdown` only

Authentication uses an `api_key` HTTP header. The configured
`[api.security] api_key_hash` is the lowercase Base16 of
`Blake2b256(secret)`; the node hashes the incoming header bytes the same
way and compares in constant time, returning HTTP `403` on any mismatch.
This header name, hash, and rejection envelope match the Scala reference
node.

`api_key_hash` is **mandatory whenever the API server is enabled** — the
node will not start without it. The only way to omit it is `[api]
disabled = true`.

The auth gate covers exactly two route families:

| Gated (require `api_key`) | Unauthenticated |
|---|---|
| `/wallet/*` (the wallet JSON API) | All read routes (`/info`, `/blocks/*`, `/peers/*`, `/utxo/*`, `/blockchain/*`, `/api/v1/*` reads) |
| `POST /node/shutdown` and `POST /api/v1/node/shutdown` | Transaction/block submission (`POST /transactions*`, `POST /blocks`, `POST /api/v1/mempool/{submit,check}`) |
| | `/mining/*`, `/utils/*`, `/metrics`, the dashboard, and `/wallet/ui*` |

This narrow gate is **deliberate Scala parity**: the Scala reference node
leaves submission and read routes unauthenticated. The consequence is that
when `public_bind = true` is set on a routable interface, transaction and
block submission, mining solution submission, and `/metrics` are all
publicly callable. The config-load error string spells this out before you
can bring the node up on a non-loopback address. Keep `/metrics` on
loopback or behind an authenticated proxy.

> Note: enabling a non-loopback bind currently produces no runtime warning
> log once `public_bind = true` is accepted — the only operator-facing
> signal is the config-load rejection you must clear to enable it. Treat
> the act of setting `public_bind = true` as the warning.

### The wallet UI is a thin client; the browser never holds keys

The wallet UI served at `/wallet/ui` is a static page (public, like the
dashboard — it is **not** behind the `api_key` gate, because the page
itself carries no secrets). It is a thin remote control for the node's
`/wallet/*` REST API: the browser never holds the master key, never
derives, and never signs. Every operation is an authenticated `fetch()` to
a `/wallet/*` route. Key material, derivation, and signing all happen
node-side; secrets are stored encrypted at rest (AES-GCM) under the data
directory's `wallet/` folder.

The only credential the browser holds is the operator `api_key` the user
pastes on first visit, kept in that tab's `sessionStorage` and sent as the
`api_key` header. The wallet password and recovery mnemonic exist only
transiently in page memory during init and recovery flows and are never
written to `sessionStorage` or `localStorage`. The recovery mnemonic is
visible on screen during initialization — anyone (or any browser
extension) with access to that page can read it while it is displayed.

Private-key export is off by default: `POST /wallet/getPrivateKey` returns
`403 Forbidden` unless the operator has explicitly set
`[wallet] expose_private_keys = true`.

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
