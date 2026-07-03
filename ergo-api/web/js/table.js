// Reusable card-row table — clip-proof (fixed flex widths + ellipsis),
// sortable, with an optional expand-to-detail drawer. Built from DOM
// nodes / textContent only (never innerHTML of caller/server data).
//
// columns: [{ key, label, width?, align?, render?(row)->Node|string, sort?(row)->any }]
// opts: { rowKey(row)->string, renderDetail?(row)->Node, initialSort?:{key,dir} }
let tableSeq = 0; // per-instance drawer-id namespace (see aria-controls below)

export function makeTable(container, columns, opts = {}) {
  const tableId = ++tableSeq;
  let rows = [];
  let sort = opts.initialSort || { key: columns[0].key, dir: -1 };
  let expanded = null;

  const table = document.createElement('div');
  table.className = 'dtable';
  table.setAttribute('role', 'table');
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
    h.setAttribute('role', 'row');
    for (const c of columns) {
      const s = document.createElement('button');
      s.className = 'dtable__th micro-label' + (c.align === 'right' ? ' dtable__c--r' : '');
      s.style.flex = c.width ? `0 0 ${c.width}px` : '1';
      s.textContent = c.label + (sort.key === c.key ? (sort.dir < 0 ? ' ▾' : ' ▴') : '');
      s.setAttribute('aria-sort', sort.key === c.key ? (sort.dir < 0 ? 'descending' : 'ascending') : 'none');
      s.setAttribute('role', 'columnheader');
      s.onclick = () => {
        sort = { key: c.key, dir: sort.key === c.key ? -sort.dir : -1 };
        draw();
      };
      h.append(s);
    }
    if (opts.renderDetail) {
      // Spacer aligning the header with the rows' expand-toggle column.
      const sp = document.createElement('span');
      sp.className = 'dtable__togglespace';
      sp.setAttribute('aria-hidden', 'true');
      h.append(sp);
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
    const nextRows = sortedRows();
    if (!nextRows.length) {
      const empty = document.createElement('div');
      empty.className = 'dtable__empty';
      empty.textContent = 'No rows to display.';
      table.append(empty);
      return;
    }
    for (const row of nextRows) {
      const r = document.createElement('div');
      r.className = 'dtable__row';
      const rk = opts.rowKey(row);
      if (expanded === rk) r.classList.add('dtable__row--open');
      for (const c of columns) r.append(cell(c, row));
      if (opts.renderDetail) {
        // A dedicated, natively-focusable toggle carries the disclosure
        // semantics. The old shape (role=button + tabindex on the whole
        // row) nested links/copy-buttons inside a button role — invalid
        // ARIA that screen readers flatten inconsistently. The row keeps a
        // pointer-only whitespace-click affordance (no role, no tabindex),
        // so mouse ergonomics are unchanged while AT sees one clean button.
        const isOpen = expanded === rk;
        // Only one drawer is open per table, so the id needs no row
        // component at all — an instance counter is collision-proof where a
        // truncated row key was not.
        const drawerId = `dtable-drawer-${tableId}`;
        const tg = document.createElement('button');
        tg.type = 'button';
        tg.className = 'dtable__toggle';
        tg.textContent = '▸';
        tg.title = isOpen ? 'collapse details' : 'expand details';
        tg.setAttribute('aria-label', 'row details');
        tg.setAttribute('aria-expanded', String(isOpen));
        if (isOpen) tg.setAttribute('aria-controls', drawerId);
        const toggle = () => {
          expanded = expanded === rk ? null : rk;
          draw();
          // Re-focus the same row's toggle after the redraw so keyboard
          // users aren't dumped to <body> by the rebuild.
          const again = table.querySelector(`[data-tg="${CSS.escape(String(rk))}"]`);
          if (again) again.focus({ preventScroll: true });
        };
        tg.dataset.tg = String(rk);
        tg.onclick = toggle;
        r.append(tg);
        r.onclick = (e) => {
          // Pointer convenience: whitespace clicks toggle too. Interactive
          // descendants (links, copy, the toggle itself) act on their own.
          if (e.target.closest('.copy, a, button')) return;
          toggle();
        };
        if (isOpen) r._drawerId = drawerId;
      }
      table.append(r);
      if (opts.renderDetail && expanded === rk) {
        const d = document.createElement('div');
        d.className = 'dtable__drawer';
        d.id = r._drawerId;
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
