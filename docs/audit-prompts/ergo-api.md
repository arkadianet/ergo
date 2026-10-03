# `ergo-api` reference-quality audit prompt

Audit `ergo-api` as the externally exposed HTTP, operator, wallet, realtime,
webhook, and embedded UI boundary of a prospective reference Rust Ergo node.
Read `docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, and `docs/codemap/ergo-api.md`. Follow the common
review-only workflow, complete file ledger, evidence rules, and report format.
Treat documentation inventories and middleware comments as claims to verify
against the current router and production node wiring.

## Mission and boundaries

Trace request/upgrade → host/proxy/auth/governor/extractor checks → handler →
trait call/compute/read lane → publication/response/OpenAPI/UI interpretation.
Include optional mounts and all error/cancellation paths. The crate owns wire
contracts, authorization, bounded work, and truthful product behavior; consensus
validity, persistence, wallet custody, and mining validity cross explicit traits.
Verify those seams without assuming the trait implementation fulfills its prose.

## Source landmarks and complete surface inventory

- Read `Cargo.toml`, `src/lib.rs`, `src/traits.rs`, `src/api_family.rs`,
  `src/auth.rs`, `src/host_guard.rs`, and all `src/types/` modules.
- Trace `src/server/{mod,scala_api,rust_api,route_registry,openapi,shared,
  handlers,assets}.rs`; inventory every builder and `ServerCtx` combination.
- Include all `src/compat/`, `src/blockchain.rs`, `src/blockchain/`,
  `src/wallet/` and native DTO submodules, `mining.rs`, `script.rs`, `utils.rs`,
  and `emission.rs`, including default/noop trait implementations.
- Include every `src/v1/` module: auth, governor, blocking reads, cursor, errors,
  routes/DTOs/tx intelligence/batch, script, accounts/scans, operator controls,
  decode registry/services/decoders, pricing, realtime, webhooks, and depth sampler.
- Read all tests wired by `tests/it/main.rs`, inline tests, captured Scala
  fixtures, OpenAPI snapshots, protocol decoder fixtures, and fixture provenance.
- Audit all `web/` HTML/CSS/JS/tests, Swagger pages, font assets/licenses, and
  every asset embedded by `src/web.rs`. `/wallet/ui*` currently redirects to the
  unified dashboard; inspect actual redirect and SPA response-header code.
- Resolve related node snapshot/API/wallet/mining/event bridge implementations,
  `ergo-indexer-types` read contracts, and `ergo-rest-json` byte reconstruction.
- Build a route ledger from actual registrations: method/path/family, capability
  mount, auth tier, middleware order, input/output schema, cost class, limits,
  trait/side effect, error envelope, OpenAPI operation, tests, and UI consumers.

## Exposure, authority, and HTTP boundaries

1. Review all public/operator/admin tiers, Scala `api_key` verification, absent
   key behavior, constant-time comparison, malformed/multiple headers, and weak
   default-key warnings. Verify each protected route fails closed as intended.
2. Verify auth is applied to the actual final mounts and aliases, including
   wallet lifecycle/reads/secrets, scans/accounts, mining, diagnostics/activity,
   node shutdown, peer/vote mutation, webhooks, and script configuration modes.
3. Review socket-derived client identity, missing `ConnectInfo`, IPv4/IPv6
   loopback, local reverse-proxy settings, forwarded-header spoofing, and admin
   hard-deny policy. Host allowlists must cover all entry points, default ports,
   malformed/duplicate Host headers, rebinding, and direct versus proxied binds.
4. Inspect method behavior, path normalization/escaping, HEAD/OPTIONS, route
   overlap, unsupported methods, unmatched routes, and trailing slashes. Check
   CORS/origin/CSRF/WS-origin behavior where relevant to browser credentials;
   report actual exposure rather than proposing unrelated blanket restrictions.
5. Inventory body/query/path limits per handler: JSON, raw bytes, hex expansion,
   arrays, strings, script source/tree, big integers, cursor/page/range/filter,
   uploads, batch items, and proof/hint bags. Check rejection occurs before
   allocation or expensive compute and covers chunked/no-Content-Length bodies.
6. Trace extractor rejections, serde errors, query duplicate/unknown fields,
   numeric overflow, missing versus empty/null inputs, and malformed identifiers
   into the correct Scala/native/v1 error envelope and status code.

## Scheduling, bounds, consistency, and shutdown

7. Establish a CPU/I/O ownership table: cheap snapshot traits, redb reads,
   compiler/interpreter/proof work, wallet KDF/signing, mining longpoll, webhook
   transport, and response reassembly. Check async workers do not block on
   synchronous work or wait for the node main loop without bounded coordination.
8. Verify `v1/blocking.rs` lane permits, queue waits, run deadlines, panics, and
   request cancellation. A timed-out `spawn_blocking` job can continue; its permit
   and memory must remain charged until actual completion, and repeated timeouts
   must not create unbounded work. Check every intended handler uses its lane.
9. Audit governor capacity/eviction/TTL, cost arithmetic, monotonic clock handling,
   per-IP/global bounds, trusted-loopback exemptions, Retry-After, and every
   heavy route. A per-IP limit alone does not bound many-client concurrency.
10. Trace all background tasks and shared singleton guards: event bridge, depth
    sampler, webhook worker/deliveries, socket tasks, and listener shutdown.
    Verify repeated router construction, new runtimes, multiple servers, and
    dropped handles use the intended state and cannot create duplicates or stale
    workers. Check startup failure rollback and graceful cancellation/join.
11. Verify snapshots combine coherent chain/mempool/indexer/wallet observations,
    especially `PoolTxDetail`, balances/UTXOs with overlays, confirmations,
    recent blocks, activity cursors, and metrics. Reorg or concurrent pool updates
    must not create fictional state or silently turn a read failure into absence.
12. Check submit/check/block/wallet mutations return correct IDs and semantic
    errors, preserve overload/shutdown/deadline distinctions, and have explicit
    behavior if the client disconnects after work was accepted. Confirm graceful
    drain allows structured shutdown errors and does not strand response tasks.

## Specialized public and operator services

13. Verify optional indexer/chain/mining/wallet/UTXO/parameter capabilities produce
    intentional mounts, 404/503 behavior, and matching descriptors. Status gates,
    height/health exceptions, halted/degraded repair state, fallible reads, and
    digest-mode UTXO stubs must reflect the real backend.
14. Check paging/cursor/range inclusivity, maximums, stable ordering, cursor
    tampering/version/reorg behavior, total counts, per-item reassembly costs,
    mempool-spent filtering, storage-rent creation-height semantics, and precision.
15. Audit batch's closed method/path allowlist and restricted in-process router:
    forbid nested batches and mutating/compute/secret surfaces, encoded-path and
    query escapes, authority overrides, and body forwarding surprises. Verify
    item/count/summed-cost/response limits, one-time charging, inherited auth,
    individual error semantics, and duplicate item-ID handling.
16. Audit script compile/reduce/evaluate and transaction build/simulate/fee/status
    services for exact cost units, recursion/source/tree/context bounds, voted
    versus assumed parameters, and honest interpretation of simulation results.
    A useful prediction must not be represented as chain acceptance or custody.
17. Review decoder registries and pricing discovery/selection/spot arithmetic:
    authenticate protocol identity from script/register structure, handle malformed
    metadata/decimals/reserves, maintain exact rational arithmetic, determinism,
    stale/missing/indexer-error distinctions, and avoid misleading price certainty.
18. Review account/scanning DTO mapping, network validation, seed/key export,
    two-step initialization/unlock, lock guards, external-secret/hint conversions,
    change-address ownership, and wallet error classifications at the node seam.
19. Verify mining candidate longpoll/deadline, optional transactions, solution
    validation errors, template sequence/metrics publication, reward address/key,
    and candidate cache coherence without duplicating consensus validation here.

## Realtime, webhooks, publication, and UI

20. Inventory actual streaming transports. Review `v1/realtime` WS upgrades,
    public channel permissions, selector validation, frame/channel/control-rate
    bounds, per-IP/global connection ceilings, heartbeat/idle timeout, and guard
    release on every exit. Do not count a documented SSE promise as implemented;
    if SSE exists in a later checkout, audit its equivalent lifecycle and limits.
21. Verify event sequence/retention/backfill/gap/truncation, confirmation and reorg
    semantics, upstream snapshot-to-event mapping, subscriber fanout, filtered
    slow consumers, bounded queues, and reconnect behavior with `web/js/ws-client.js`.
22. Audit webhook URL policy and production transport together: scheme/credentials,
    host/IP/IPv6 forms, DNS resolution/rebinding, private/link-local/loopback targets,
    redirects, TLS, proxies, response-size/timeout limits, and configured exceptions.
23. Check signed raw-body stability, timestamp units, secret generation/redaction,
    subscription authorization, event filtering, at-least-once IDs/dedup, retries/
    jitter/in-flight bounds, deletion/pause races, queue overflow, auto-disable,
    shutdown, and disclosed restart/delivery durability semantics.
24. Reconcile runtime route inventory with `server/openapi.rs`, v1 fragments,
    `web/openapi.yaml`, served Scala/Rust specs, schema references, auth/security
    declarations, defaults, operation-ID uniqueness, examples, and snapshots.
    Publication must describe mounted capabilities and real error behavior.
25. Audit dashboard/wallet JS for DOM injection, hostile metadata/log strings,
    API-key/mnemonic/password lifetime, browser storage/cache/history/bfcache,
    late responses after auth/lock/network changes, aborts, stale data labels,
    exact ERG/token/ID handling, keyboard/accessibility, and responsive layouts.
26. Verify SPA CSP/no-store/referrer/frame headers cover mnemonic-bearing HTML,
    assets, redirects, and error responses appropriately. Inspect Swagger external
    resources separately. Logs/traces must omit credential bodies and sensitive
    query strings; activity exports must reflect authorization and retention.

## Required evidence, verification, and completion

- Exercise a real-router capability/auth matrix with missing/valid/invalid keys,
  direct/proxy/nonloopback callers, unsupported modes, malformed headers/bodies,
  and aliases. Verify protected trait methods are never called on rejection.
- Exercise read failure versus missing value, stalled blocking work after timeout,
  saturated lanes/governor, cancellation, submit shutdown, large batch/proof/script
  input, slow WS consumers, backfill gaps, and failing/redirecting webhook sinks.
- Use captured Scala responses for error/wire parity and independent node-wallet
  and byte-decoding evidence; no-op stubs establish routing, not production safety.
- Use common checks plus `cargo test --locked -p ergo-api` and the dependency-free JS suite
  `node --test ergo-api/web/tests/*.test.mjs` when Node is available. Inspect the
  optional browser test separately; prefer the product preview tools for browser
  inspection. Record unavailable browser/Node/live-oracle coverage explicitly.

Complete when the route and file ledgers cover every mount, handler, task, schema,
asset, test, comment, and fixture; authority/limits/error/publication seams have
evidence; and unverified capability, lifecycle, parity, and UI claims remain
explicit in the common report. Do not equate an OpenAPI snapshot with runtime
coverage or a passing handler stub with a safe production node.
