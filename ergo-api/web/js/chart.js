// Real charts for the operator dashboard: an axis-labelled line/area chart
// and a bar histogram, both with pointer readouts. Zero-dep SVG via
// createElementNS — data flows through textContent / attributes only, never
// innerHTML. Colors are CSS var() strings applied via element.style so all
// three themes work without getComputedStyle.
//
// Layout strategy: the SVG stretches (preserveAspectRatio="none" over a fixed
// 640-unit internal width) while ALL text lives in HTML around it — y-labels
// in an absolutely-positioned column, x-labels in a flex row underneath. That
// sidesteps stretched-text distortion entirely; series strokes stay crisp via
// vector-effect: non-scaling-stroke.
const NS = 'http://www.w3.org/2000/svg';
const W = 640; // internal x-units; the SVG scales to its container

function svgEl(tag, attrs = {}) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  return e;
}

function div(cls, text) {
  const d = document.createElement('div');
  if (cls) d.className = cls;
  if (text != null) d.textContent = text;
  return d;
}

function span(cls, text) {
  const s = document.createElement('span');
  if (cls) s.className = cls;
  if (text != null) s.textContent = text;
  return s;
}

const noop = (v) => String(v);

// Shared scaffold: readout row + plot area (y-labels + svg) + x-labels row.
function scaffold(h) {
  const el = div('chart');
  const readout = div('chart__readout');
  readout.append(span('muted', '')); // stable child; textContent swapped on hover
  const plot = div('chart__plot');
  const ylab = div('chart__ylabels');
  const svg = svgEl('svg', {
    viewBox: `0 0 ${W} ${h}`,
    preserveAspectRatio: 'none',
    width: '100%',
    height: h,
    'aria-hidden': 'true',
  });
  svg.style.display = 'block';
  plot.append(ylab, svg);
  const xlab = div('chart__xlabels');
  el.append(readout, plot, xlab);
  return { el, readout: readout.firstChild, ylab, svg, xlab };
}

function setLabels(host, texts) {
  host.replaceChildren(...texts.map((t) => span(null, t)));
}

// Horizontal gridlines at the given height fractions.
function grid(svg, h, fracs) {
  for (const f of fracs) {
    const y = f * h;
    const l = svgEl('line', {
      x1: 0,
      y1: y,
      x2: W,
      y2: y,
      'stroke-width': 1,
      'vector-effect': 'non-scaling-stroke',
    });
    l.style.stroke = 'var(--divider)';
    svg.append(l);
  }
}

// Line/area chart over [{x, y}] points (sorted by x ascending).
// opts: { h?, color?, area?, xFmt?, yFmt?, label? (aria summary prefix) }
// Returns { el, update(points) }.
export function lineChart({ h = 150, color = 'var(--blue)', area = true, xFmt = noop, yFmt = noop, label = 'chart' } = {}) {
  const ui = scaffold(h);
  ui.el.setAttribute('role', 'img');
  let pts = [];
  let scaled = []; // [{px, py, x, y}]

  function update(points) {
    pts = Array.isArray(points) ? points.filter((p) => p && Number.isFinite(p.y)) : [];
    ui.svg.replaceChildren();
    scaled = [];
    if (pts.length < 2) {
      // Clear the hover expandos too — they'd otherwise point at detached
      // nodes from the previous render.
      ui.svg._cross = null;
      ui.svg._dot = null;
      setLabels(ui.ylab, []);
      setLabels(ui.xlab, []);
      ui.readout.textContent = 'not enough data';
      ui.el.setAttribute('aria-label', `${label}: not enough data`);
      return;
    }
    const ys = pts.map((p) => p.y);
    let lo = Math.min(...ys);
    let hi = Math.max(...ys);
    if (hi === lo) {
      // flat series: pad so the line sits mid-chart instead of on an edge
      hi += Math.abs(hi) * 0.01 + 1;
      lo -= Math.abs(lo) * 0.01 + 1;
    }
    const pad = (hi - lo) * 0.06;
    hi += pad;
    lo -= pad;
    const step = W / (pts.length - 1);
    scaled = pts.map((p, i) => ({
      px: i * step,
      py: h - ((p.y - lo) / (hi - lo)) * h,
      x: p.x,
      y: p.y,
    }));

    grid(ui.svg, h, [0.02, 0.5, 0.98]);
    const d = scaled.map((p, i) => `${i ? 'L' : 'M'}${p.px},${p.py}`).join(' ');
    if (area) {
      const a = svgEl('path', { d: `${d} L${W},${h} L0,${h} Z` });
      a.style.fill = color;
      a.style.fillOpacity = '0.14';
      ui.svg.append(a);
    }
    const line = svgEl('path', {
      d,
      fill: 'none',
      'stroke-width': 1.6,
      'stroke-linejoin': 'round',
      'vector-effect': 'non-scaling-stroke',
    });
    line.style.stroke = color;
    ui.svg.append(line);

    // hover crosshair + marker (hidden until pointermove)
    const cross = svgEl('line', {
      y1: 0,
      y2: h,
      'stroke-width': 1,
      'stroke-dasharray': '3 3',
      'vector-effect': 'non-scaling-stroke',
      visibility: 'hidden',
    });
    cross.style.stroke = 'var(--tx3)';
    const dot = svgEl('circle', { r: 3, visibility: 'hidden' });
    dot.style.fill = color;
    ui.svg.append(cross, dot);
    ui.svg._cross = cross;
    ui.svg._dot = dot;

    const mid = pts[Math.floor((pts.length - 1) / 2)];
    const midY = lo + (hi - lo) / 2;
    setLabels(ui.ylab, [yFmt(hi), yFmt(midY), yFmt(lo)]);
    setLabels(ui.xlab, [xFmt(pts[0].x), xFmt(mid.x), xFmt(pts[pts.length - 1].x)]);
    ui.readout.textContent = `${xFmt(pts[pts.length - 1].x)} · ${yFmt(pts[pts.length - 1].y)}`;
    ui.el.setAttribute('aria-label', `${label}: ${pts.length} points, ${yFmt(lo)} to ${yFmt(hi)}`);
  }

  ui.svg.addEventListener('pointermove', (e) => {
    if (!scaled.length) return;
    const rect = ui.svg.getBoundingClientRect();
    const fx = ((e.clientX - rect.left) / rect.width) * W;
    let i = Math.round(fx / (W / (scaled.length - 1)));
    i = Math.max(0, Math.min(scaled.length - 1, i));
    const p = scaled[i];
    ui.svg._cross?.setAttribute('x1', p.px);
    ui.svg._cross?.setAttribute('x2', p.px);
    ui.svg._cross?.setAttribute('visibility', 'visible');
    ui.svg._dot?.setAttribute('cx', p.px);
    ui.svg._dot?.setAttribute('cy', p.py);
    ui.svg._dot?.setAttribute('visibility', 'visible');
    ui.readout.textContent = `${xFmt(p.x)} · ${yFmt(p.y)}`;
  });
  ui.svg.addEventListener('pointerleave', () => {
    ui.svg._cross?.setAttribute('visibility', 'hidden');
    ui.svg._dot?.setAttribute('visibility', 'hidden');
    if (pts.length) ui.readout.textContent = `${xFmt(pts[pts.length - 1].x)} · ${yFmt(pts[pts.length - 1].y)}`;
  });

  return { el: ui.el, update };
}

// Bar histogram over [{label, value}] bins.
// opts: { h?, color?, yFmt?, label? } — bin labels render under the plot when
// there are ≤ 10 bins (else first/last only). Returns { el, update(bins) }.
export function barChart({ h = 150, color = 'var(--purple)', yFmt = noop, label = 'histogram' } = {}) {
  const ui = scaffold(h);
  ui.el.setAttribute('role', 'img');
  let bins = [];
  let bars = [];

  function update(next) {
    bins = Array.isArray(next) ? next.filter((b) => b && Number.isFinite(b.value)) : [];
    ui.svg.replaceChildren();
    bars = [];
    if (!bins.length) {
      setLabels(ui.ylab, []);
      setLabels(ui.xlab, []);
      ui.readout.textContent = 'no data';
      ui.el.setAttribute('aria-label', `${label}: no data`);
      return;
    }
    const max = Math.max(...bins.map((b) => b.value), 1);
    grid(ui.svg, h, [0.02, 0.5, 0.98]);
    const bw = W / bins.length;
    bins.forEach((b, i) => {
      // Clamp FIRST, then derive y from the clamped height — deriving y
      // from the raw height while clamping the height would push a tiny
      // bar's bottom edge past the baseline (CodeRabbit, PR #151).
      const bh = Math.max((b.value / max) * (h * 0.96), b.value > 0 ? 2 : 0);
      const r = svgEl('rect', {
        x: i * bw + bw * 0.12,
        y: h - bh,
        width: bw * 0.76,
        height: bh,
        rx: 2,
      });
      r.style.fill = color;
      r.style.fillOpacity = '0.75';
      ui.svg.append(r);
      bars.push(r);
    });
    setLabels(ui.ylab, [yFmt(max), yFmt(max / 2), '0']);
    setLabels(ui.xlab, bins.length <= 10 ? bins.map((b) => b.label) : [bins[0].label, bins[bins.length - 1].label]);
    ui.readout.textContent = '';
    ui.el.setAttribute('aria-label', `${label}: ${bins.length} bins, max ${yFmt(max)}`);
  }

  ui.svg.addEventListener('pointermove', (e) => {
    if (!bins.length) return;
    const rect = ui.svg.getBoundingClientRect();
    let i = Math.floor(((e.clientX - rect.left) / rect.width) * bins.length);
    i = Math.max(0, Math.min(bins.length - 1, i));
    bars.forEach((r, j) => {
      r.style.fillOpacity = j === i ? '1' : '0.55';
    });
    ui.readout.textContent = `${bins[i].label} · ${yFmt(bins[i].value)}`;
  });
  ui.svg.addEventListener('pointerleave', () => {
    bars.forEach((r) => {
      r.style.fillOpacity = '0.75';
    });
    ui.readout.textContent = '';
  });

  return { el: ui.el, update };
}
