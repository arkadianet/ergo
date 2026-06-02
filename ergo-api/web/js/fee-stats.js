// Pure fee-distribution stats + log-scale histogram. No DOM/I-O.
export function stats(vals) {
  if (!vals.length) return { min: 0, max: 0, median: 0, mean: 0, mode: 0 };
  const s = [...vals].sort((a, b) => a - b);
  const min = s[0];
  const max = s[s.length - 1];
  const mid = s.length >> 1;
  const median = s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
  const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
  const freq = new Map();
  let mode = s[0];
  let best = 0;
  for (const v of vals) {
    const n = (freq.get(v) || 0) + 1;
    freq.set(v, n);
    if (n > best) {
      best = n;
      mode = v;
    }
  }
  return { min, max, median, mean, mode };
}

// Counts on a log-spaced axis between the smallest and largest positive
// value — the honest way to show a wide fee/B dynamic range.
export function logHistogram(vals, n = 24) {
  const pos = vals.filter((v) => v > 0);
  if (!pos.length) return { counts: [], lo: 0, hi: 0 };
  const lo = Math.min(...pos);
  const hi = Math.max(...pos);
  const counts = new Array(n).fill(0);
  if (hi === lo) {
    counts[0] = pos.length;
    return { counts, lo, hi };
  }
  const llo = Math.log(lo);
  const lhi = Math.log(hi);
  for (const v of pos) {
    let i = Math.floor(((Math.log(v) - llo) / (lhi - llo)) * n);
    if (i < 0) i = 0;
    if (i >= n) i = n - 1;
    counts[i]++;
  }
  return { counts, lo, hi };
}

// Position of a value on the log axis, as a fraction in [0,1].
export function logFrac(v, lo, hi) {
  if (!(v > 0) || !(lo > 0) || hi <= lo) return 0;
  return (Math.log(v) - Math.log(lo)) / (Math.log(hi) - Math.log(lo));
}

if (new URLSearchParams(location.search).has('selftest')) {
  const r = stats([1, 2, 2, 3, 100]);
  console.assert(r.median === 2 && r.mode === 2 && r.min === 1 && r.max === 100, 'fee-stats stats', r);
  const h = logHistogram([1, 10, 100, 1000], 4);
  console.assert(h.lo === 1 && h.hi === 1000 && h.counts.reduce((a, b) => a + b, 0) === 4, 'fee-stats hist', h);
  console.assert(Math.abs(logFrac(10, 1, 100) - 0.5) < 1e-9, 'fee-stats logFrac');
  console.log('fee-stats.js selftest done');
}
