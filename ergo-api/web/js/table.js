// Reusable card-row table — clip-proof (fixed flex widths + ellipsis),
// sortable, with an optional expand-to-detail drawer. Built from DOM
// nodes / textContent only (never innerHTML of caller/server data).
//
// columns: [{ key, label, width?, align?, render?(row)->Node|string, sort?(row)->any }]
// opts: { rowKey(row)->string, renderDetail?(row)->Node, initialSort?:{key,dir} }
export function makeTable(container, columns, opts = {}) {
  let rows = [];
  let sort = opts.initialSort || { key: columns[0].key, dir: -1 };
  let expanded = null;

  const table = document.createElement('div');
  table.className = 'dtable';
  container.replaceChildren(table);

  function cell(c, row) {
    const d = document.createElement('span');
    d.className = 'dtable__c' + (c.align === 'right' ? ' dtable__c--r' : '');
    d.style.flex = c.width ? `0 0 ${c.width}px` : '1';
    d.dataset.label = c.label; // mobile card label
    const v = c.render ? c.render(row) : row[c.key];
    if (v instanceof Node) d.append(v);
    else d.textContent = v == null ? '—' : String(v);
    return d;
  }

  function header() {
    const h = document.createElement('div');
    h.className = 'dtable__head';
    for (const c of columns) {
      const s = document.createElement('button');
      s.className = 'dtable__th micro-label' + (c.align === 'right' ? ' dtable__c--r' : '');
      s.style.flex = c.width ? `0 0 ${c.width}px` : '1';
      s.textContent = c.label + (sort.key === c.key ? (sort.dir < 0 ? ' ▾' : ' ▴') : '');
      s.setAttribute('aria-sort', sort.key === c.key ? (sort.dir < 0 ? 'descending' : 'ascending') : 'none');
      s.onclick = () => {
        sort = { key: c.key, dir: sort.key === c.key ? -sort.dir : -1 };
        draw();
      };
      h.append(s);
    }
    return h;
  }

  function sortedRows() {
    const c = columns.find((x) => x.key === sort.key);
    const val = (c && c.sort) || ((r) => r[sort.key]);
    return [...rows].sort((a, b) => {
      const va = val(a);
      const vb = val(b);
      return (va > vb ? 1 : va < vb ? -1 : 0) * sort.dir;
    });
  }

  function draw() {
    table.replaceChildren(header());
    for (const row of sortedRows()) {
      const r = document.createElement('div');
      r.className = 'dtable__row';
      const rk = opts.rowKey(row);
      if (expanded === rk) r.classList.add('dtable__row--open');
      for (const c of columns) r.append(cell(c, row));
      if (opts.renderDetail) {
        r.tabIndex = 0;
        const toggle = (e) => {
          if (e.target.closest('.copy')) return;
          expanded = expanded === rk ? null : rk;
          draw();
        };
        r.onclick = toggle;
        r.onkeydown = (e) => {
          // Let a focused copy button handle its own Enter/Space (don't
          // preventDefault its native activation before it fires).
          if (e.target.closest('.copy')) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            toggle(e);
          }
        };
      }
      table.append(r);
      if (opts.renderDetail && expanded === rk) {
        const d = document.createElement('div');
        d.className = 'dtable__drawer';
        d.append(opts.renderDetail(row));
        table.append(d);
      }
    }
  }

  return {
    update(next) {
      rows = next || [];
      draw();
    },
  };
}

export function copyBtn(text) {
  // A real <button> so it's keyboard-focusable/operable; the row toggle
  // already ignores clicks inside `.copy`.
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'copy';
  b.textContent = '⧉';
  b.title = 'copy';
  b.setAttribute('aria-label', 'copy');
  b.onclick = () => navigator.clipboard?.writeText(text);
  return b;
}
