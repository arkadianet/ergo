// EIP-4 token name/decimals resolution — shared by explorer.js and wallet.js.
//
// Asset lists on the wire carry only {tokenId, amount}; without the mint
// box's EIP-4 registers a 2-decimal token renders "100" for 1.00 and every
// list shows a bare hex id instead of a name. This batches
// POST /blockchain/tokens lookups and caches per-id for the session (mint
// metadata is immutable). Requires the extra index; a caller that tracks its
// own indexer-availability signal should pass `enabled: false` while it's
// down/syncing rather than spend a request that can only 503.
import { num } from './format.js';

const tokenMeta = new Map(); // tokenId → {name, decimals}

// Unicode bidi/zero-width formatting controls: stripped from DISPLAY names so
// a hostile mint can't reorder or invisibly pad the label. The raw name stays
// reachable via the tokenId (always shown alongside, e.g. in a title attr).
const BIDI_CONTROLS = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

// EIP-4 decimals is attacker-controlled mint data decoded from a register —
// a huge value would turn 10**d / padStart(d+1) into a RangeError or a giant
// allocation at render time. u64 amounts have ≤ 20 digits, so clamp to
// [0, 19]; anything outside renders raw.
export function saneDecimals(d) {
  return Number.isInteger(d) && d > 0 && d <= 19 ? d : 0;
}

// Read-only POST (the batch token route). Deliberately not api-client's
// postJson: that helper is for gated writes — it attaches the api_key and
// reports 2xx as key-valid, which an ungated read would false-confirm.
async function postReadJson(path, bodyVal) {
  try {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(bodyVal),
    });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

export async function fetchTokenMeta(ids, enabled = true) {
  if (!enabled) return;
  const misses = [...new Set(ids)].filter((id) => id && !tokenMeta.has(id));
  if (!misses.length) return;
  // One batched lookup instead of a per-token fan-out — a 100-asset tx costs
  // one request. Only SUCCESSFUL lookups are cached, so a transient failure
  // retries on the next view instead of pinning raw amounts for the session.
  const got = await postReadJson('/blockchain/tokens', misses);
  if (!Array.isArray(got)) return;
  for (const t of got) {
    if (t?.id) {
      tokenMeta.set(t.id, {
        name: (t.name || '').replace(BIDI_CONTROLS, ''),
        decimals: saneDecimals(t.decimals),
      });
    }
  }
}

export function getTokenMeta(tid) {
  return tokenMeta.get(tid);
}

export function getDecimals(tid) {
  return tokenMeta.get(tid)?.decimals || 0;
}

// Cleaned, length-capped display name, or '' if unknown/blank.
export function tokenName(tid) {
  const m = tokenMeta.get(tid);
  if (!m?.name?.trim()) return '';
  // Code-point-safe truncation: a bare String.slice counts UTF-16 units and
  // can bisect a surrogate pair (emoji / astral chars) into a lone "�".
  // Array.from splits by code points, so pairs stay intact; ZWJ-composed
  // clusters can't be split either — BIDI_CONTROLS already strips ZWJ.
  return Array.from(m.name.trim()).slice(0, 32).join('');
}

// Bare (no thousands separator) decimal-string shift — round-trips through
// parseTokenAmount, unlike decimalize()'s locale-formatted output. Used to
// prefill an editable amount field (e.g. a "max" button) with the exact
// available balance.
function rawDecimalString(amount, d) {
  if (!Number.isSafeInteger(amount)) return String(amount / 10 ** d);
  const neg = amount < 0;
  const s = BigInt(Math.abs(amount))
    .toString()
    .padStart(d + 1, '0');
  const whole = s.slice(0, s.length - d);
  const frac = s.slice(s.length - d).replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`;
}

// Integer-exact decimal shift (string math via BigInt) for safe integers;
// unsafe magnitudes fall back to an approximate float shift, marked ≈.
export function decimalize(amount, d) {
  if (amount == null) return '—';
  if (!Number.isSafeInteger(amount)) return `≈${num(amount / 10 ** d)}`;
  const neg = amount < 0;
  const s = BigInt(Math.abs(amount))
    .toString()
    .padStart(d + 1, '0');
  const whole = num(Number(s.slice(0, s.length - d)));
  const frac = s.slice(s.length - d).replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`;
}

// Exact decimal-string form of an amount, suitable for prefilling an
// editable input (unlike decimalize(), which locale-formats for display).
export function maxDecimalString(amount, d) {
  return d > 0 ? rawDecimalString(amount, d) : String(amount);
}

// Cache-driven amount display: decimal-adjusted when the token's EIP-4
// decimals are known and non-zero, raw otherwise. `amt` mirrors explorer.js's
// bare-number formatter (u64 wire, not yet BigInt-safe server-side).
export function amt(v) {
  if (v == null) return '—';
  return Number.isSafeInteger(v) ? num(v) : `≈${num(v)}`;
}

export function tokenAmt(tid, amount) {
  const m = tokenMeta.get(tid);
  return m && m.decimals > 0 ? decimalize(amount, m.decimals) : amt(amount);
}

// Parse a decimal-string amount into an exact integer token-count (BigInt),
// given the token's known decimals (0 for an unknown/raw token — integer
// only, same as before metadata resolution existed). Mirrors format.js's
// nanoErgFromDecimal but for arbitrary decimal places.
export function parseTokenAmount(str, decimals) {
  const s = String(str).trim();
  if (decimals > 0) {
    if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('not a decimal number');
    const [whole, frac = ''] = s.split('.');
    if (frac.length > decimals) throw new Error(`more than ${decimals} decimal place${decimals > 1 ? 's' : ''}`);
    return BigInt(whole || '0') * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals));
  }
  if (!/^\d+$/.test(s)) throw new Error('must be a positive integer');
  return BigInt(s);
}
