// Pure display formatters. No DOM, no I/O — testable in isolation.
export const NANO = 1_000_000_000n;

export function erg(nanoErg) {
  if (nanoErg == null) return '—';
  const n = BigInt(nanoErg);
  const whole = n / NANO;
  const frac = (n % NANO).toString().padStart(9, '0');
  return `${whole}.${frac}`.replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '.0');
}

export function bytes(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(b);
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export function truncMiddle(s, head = 6, tail = 6) {
  if (!s || s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

// Parse a decimal-ERG string into exact BigInt nanoErg (9 dp), no float. Throws
// on malformed input or more than 9 fractional digits. Used by wallet send so a
// large amount is never silently corrupted by `Number * 1e9`.
export function nanoErgFromDecimal(str) {
  const s = String(str).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('not a decimal number');
  const [whole, frac = ''] = s.split('.');
  if (frac.length > 9) throw new Error('more than 9 decimal places');
  return BigInt(whole) * NANO + BigInt((frac + '000000000').slice(0, 9));
}

export function ageMs(ms) {
  if (ms == null) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

export function num(n) {
  return n == null ? '—' : Number(n).toLocaleString('en-US');
}

// Coarse duration from seconds: "42s" / "6m 4s" / "3h 12m" / "6d 4h".
export function dur(s) {
  if (s == null) return '—';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

if (new URLSearchParams(location.search).has('selftest')) {
  const eq = (a, b, m) => console.assert(a === b, `format ${m}: ${a} !== ${b}`);
  eq(erg(1_500_000_000n), '1.5', 'erg 1.5');
  eq(erg(1_250_000n), '0.00125', 'erg sub');
  eq(erg(5_000_000_000n), '5.0', 'erg whole');
  eq(bytes(3_355_443), '3.2 MB', 'bytes');
  eq(truncMiddle('a'.repeat(64)), 'aaaaaa…aaaaaa', 'trunc');
  eq(ageMs(42_000), '42s', 'age s');
  eq(ageMs(7_400_000), '2h', 'age h');
  eq(String(nanoErgFromDecimal('1.5')), '1500000000', 'nanoErg 1.5');
  eq(String(nanoErgFromDecimal('0.00125')), '1250000', 'nanoErg sub');
  eq(String(nanoErgFromDecimal('5')), '5000000000', 'nanoErg whole');
  let threw = false;
  try {
    nanoErgFromDecimal('1.2345678901');
  } catch {
    threw = true;
  }
  console.assert(threw, 'format nanoErg >9dp should throw');
  console.log('format.js selftest done');
}
