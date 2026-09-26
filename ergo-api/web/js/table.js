// Reusable card-row table with wrapping values and responsive detail cards,
// sortable, with an optional expand-to-detail drawer. Built from DOM
// nodes / textContent only (never innerHTML of caller/server data).
//
// columns: [{ key, label, width?, align?, render?(row)->Node|string, sort?(row)->any }]
// opts: { rowKey(row)->string, renderDetail?(row)->Node, initialSort?:{key,dir} }
let tableSeq = 0; // per-instance drawer-id namespace (see aria-controls below)

export function makeTable(container, columns, opts = {}) {
  container.classList.add('dtable-host');
  const tableId = ++tableSeq;
  let rows = [];
  let sort = opts.initialSort || { key: columns[0].key, dir: -1 };
  let expanded = null;
  let pendingDraw = false;

  const table = document.createElement('div');
  table.className = 'dtable';
  table.setAttribute('role', 'table');
  table.setAttribute('aria-label', opts.label || 'Results');
  const mobileSort = document.createElement('div');
  mobileSort.className = 'dtable__mobile-sort';
  const sortLabel = document.createElement('label');
  sortLabel.textContent = 'Sort by ';
  const sortSelect = document.createElement('select');
  sortSelect.className = 'select';
  for (const c of columns) {
    const option = document.createElement('option');
    option.value = c.key;
    option.textContent = c.label;
    sortSelect.append(option);
  }
  sortLabel.append(sortSelect);
  const sortDirection = document.createElement('button');
  sortDirection.type = 'button';
  sortDirection.className = 'btn btn--ghost';
  mobileSort.append(sortLabel, sortDirection);
  sortSelect.onchange = () => { sort.key = sortSelect.value; draw(); };
  sortDirection.onclick = () => { sort.dir *= -1; draw(); };
  container.replaceChildren(mobileSort, table);
  table.addEventListener('focusout', () => {
    setTimeout(() => {
      if (pendingDraw && !table.contains(document.activeElement)) draw();
    }, 0);
  });

  function cell(c, row) {
    const d = document.createElement('span');
    d.className = 'dtable__c' + (c.align === 'right' ? ' dtable__c--r' : '');
    d.setAttribute('role', 'cell');
    d.style.flex = c.width ? `0 1 ${c.width}px` : '1 1 140px';
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
      const column = document.createElement('span');
      column.className = 'dtable__heading';
      column.style.flex = c.width ? `0 1 ${c.width}px` : '1 1 140px';
      column.setAttribute('role', 'columnheader');
      column.setAttribute('aria-sort', sort.key === c.key ? (sort.dir < 0 ? 'descending' : 'ascending') : 'none');
      const s = document.createElement('button');
      s.type = 'button';
      s.className = 'dtable__th micro-label' + (c.align === 'right' ? ' dtable__c--r' : '');
      s.dataset.sort = c.key;
      s.textContent = c.label + (sort.key === c.key ? (sort.dir < 0 ? ' ▾' : ' ▴') : '');
      s.setAttribute('aria-label', `Sort by ${c.label}`);
      s.onclick = () => {
        sort = { key: c.key, dir: sort.key === c.key ? -sort.dir : -1 };
        draw();
        table.querySelector(`[data-sort="${CSS.escape(c.key)}"]`)?.focus({ preventScroll: true });
      };
      column.append(s);
      h.append(column);
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
    pendingDraw = false;
    sortSelect.value = sort.key;
    sortDirection.textContent = sort.dir < 0 ? 'Descending ↓' : 'Ascending ↑';
    table.replaceChildren(header());
    const nextRows = sortedRows();
    if (!nextRows.length) {
      const empty = document.createElement('div');
      empty.className = 'dtable__empty';
      empty.setAttribute('role', 'row');
      const content = document.createElement('span');
      content.setAttribute('role', 'cell');
      content.setAttribute('aria-colspan', String(columns.length + (opts.renderDetail ? 1 : 0)));
      content.textContent = typeof opts.emptyMessage === 'function' ? opts.emptyMessage() : opts.emptyMessage || 'No results available.';
      empty.append(content);
      table.append(empty);
      return;
    }
    for (const row of nextRows) {
      const r = document.createElement('div');
      r.className = 'dtable__row';
      r.setAttribute('role', 'row');
      if (opts.renderDetail) r.classList.add('dtable__row--expandable');
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
        tg.setAttribute('aria-label', `${isOpen ? 'Hide' : 'Show'} details for ${rk}`);
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
        const toggleCell = document.createElement('span');
        toggleCell.className = 'dtable__togglecell';
        toggleCell.setAttribute('role', 'cell');
        toggleCell.append(tg);
        r.append(toggleCell);
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
        d.setAttribute('role', 'row');
        const content = document.createElement('div');
        content.setAttribute('role', 'cell');
        content.setAttribute('aria-colspan', String(columns.length + 1));
        content.append(opts.renderDetail(row));
        d.append(content);
        table.append(d);
      }
    }
  }

  return {
    update(next) {
      rows = next || [];
      if (table.contains(document.activeElement)) { pendingDraw = true; return; }
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
  b.onclick = async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      b.textContent = '✓';
      b.setAttribute('aria-label', 'Copied');
      b.title = 'Copied';
    } catch {
      b.textContent = '!';
      b.setAttribute('aria-label', 'Copy failed; select and copy the value manually');
      b.title = 'Copy failed; select and copy the value manually';
    }
    setTimeout(() => {
      b.textContent = '⧉'; b.title = 'copy'; b.setAttribute('aria-label', 'copy');
    }, 2000);
  };
  return b;
}
