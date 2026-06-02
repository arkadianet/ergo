// Tiny inline-SVG renderers: a plain sparkline (cockpit panels) and a
// smoothed area curve (mempool fee distribution). Built with
// createElementNS — no innerHTML. Colors are CSS var() strings set via
// element.style, so they re-theme automatically with no getComputedStyle.
const NS = 'http://www.w3.org/2000/svg';

function svgEl(tag, attrs = {}) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  return e;
}

function frame(w, h) {
  const s = svgEl('svg', {
    viewBox: `0 0 ${w} ${h}`,
    preserveAspectRatio: 'none',
    width: '100%',
    height: h,
  });
  s.style.display = 'block';
  return s;
}

// Map values to [x,y] points across the viewBox (min→bottom, max→top).
function points(values, w, h, pad = 1) {
  if (!values.length) return [];
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const step = values.length > 1 ? w / (values.length - 1) : w;
  return values.map((v, i) => [i * step, h - pad - ((v - min) / span) * (h - 2 * pad)]);
}

export function sparkline(values, { color = 'var(--accent)', w = 90, h = 16 } = {}) {
  const s = frame(w, h);
  const p = points(values, w, h);
  if (p.length > 1) {
    const line = svgEl('polyline', {
      points: p.map(([x, y]) => `${x},${y}`).join(' '),
      fill: 'none',
      'stroke-width': 1.2,
      'stroke-linejoin': 'round',
      'stroke-linecap': 'round',
    });
    line.style.stroke = color;
    s.append(line);
  }
  return s;
}

// Catmull-Rom → cubic-bezier smoothing for a flowing curve.
function smoothPathD(p) {
  if (p.length < 2) return p.length ? `M${p[0][0]},${p[0][1]}` : '';
  let d = `M${p[0][0]},${p[0][1]}`;
  for (let i = 0; i < p.length - 1; i++) {
    const p0 = p[i - 1] || p[i];
    const p1 = p[i];
    const p2 = p[i + 1];
    const p3 = p[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

// Smoothed filled area for a distribution (e.g. fee/B bucket counts),
// with an optional dashed median marker positioned by fraction [0,1].
export function feeCurve(counts, { medianFrac = null, color = 'var(--blue)', w = 600, h = 30 } = {}) {
  const s = frame(w, h);
  const p = points(counts, w, h, 3);
  if (p.length > 1) {
    const d = smoothPathD(p);
    const area = svgEl('path', { d: `${d} L${w},${h} L0,${h} Z`, fill: color });
    area.style.fillOpacity = '0.28';
    s.append(area);
    const line = svgEl('path', { d, fill: 'none', 'stroke-width': 1.3 });
    line.style.stroke = color;
    s.append(line);
  }
  if (medianFrac != null) {
    const x = Math.max(0, Math.min(1, medianFrac)) * w;
    const med = svgEl('line', { x1: x, y1: 0, x2: x, y2: h, 'stroke-width': 1, 'stroke-dasharray': '2 2' });
    med.style.stroke = 'var(--accent)';
    s.append(med);
  }
  return s;
}
