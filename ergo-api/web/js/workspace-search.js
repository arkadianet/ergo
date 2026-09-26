// Local navigation and chain lookup entry point. Opening the dialog does not
// navigate, fetch data, or change a draft. Native dialog supplies focus trapping
// and Escape dismissal; results are ordinary keyboard-accessible buttons.
const destinations = [
  ['overview', 'Overview', 'Node health and chain progress'],
  ['explorer', 'Explorer', 'Blocks, transactions, addresses and assets'],
  ['peers', 'Peers', 'Network connections and peer details'],
  ['mempool', 'Mempool', 'Pending transactions and fees'],
  ['mining', 'Mining', 'Mining readiness and network distribution'],
  ['voting', 'Voting', 'Protocol parameters and voting targets'],
  ['wallet', 'Wallet', 'Balances, addresses and payments'],
];

export function initWorkspaceSearch({ trigger, canOpen, navigate, search }) {
  const dialog = document.createElement('dialog');
  dialog.className = 'dialog command-search';
  dialog.setAttribute('aria-label', 'Search workspace and chain');
  dialog.innerHTML = `
    <form class="command-search__form">
      <label for="workspace-query">Search workspace or chain</label>
      <div class="command-search__input"><input id="workspace-query" type="search" autocomplete="off" spellcheck="false" placeholder="Page, block height, transaction ID or address"><button type="button" class="btn btn--ghost" data-close aria-label="Close search">Esc</button></div>
    </form>
    <div class="command-search__results" data-results></div>
    <div class="command-search__footer"><span data-count role="status"></span><span>↑ ↓ navigate · Enter open</span></div>`;
  document.body.append(dialog);
  const input = dialog.querySelector('input');
  const results = dialog.querySelector('[data-results]');
  let previousFocus = null;
  function item(title, description, action, kind) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'command-search__result';
    const copy = document.createElement('span');
    const label = document.createElement('strong');
    const detail = document.createElement('span');
    const badge = document.createElement('span');
    label.textContent = title;
    detail.textContent = description;
    badge.textContent = kind;
    badge.className = 'command-search__kind';
    copy.append(label, detail);
    button.append(copy, badge);
    button.onclick = () => { previousFocus = null; dialog.close(); action(); };
    return button;
  }
  function openPage(id) {
    const focusHeading = () => {
      const page = document.getElementById(`section-${id}`);
      const heading = page && !page.hidden && page.querySelector('h1');
      if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus({ preventScroll: true }); }
    };
    const sameRoute = location.hash === `#${id}`;
    // Run after the router mounts the destination; a veto leaves it hidden.
    if (!sameRoute) window.addEventListener('hashchange', focusHeading, { once: true });
    navigate(id);
    if (sameRoute) focusHeading();
  }
  function render() {
    const query = input.value.trim();
    const matches = destinations.filter(d => d.join(' ').toLowerCase().includes(query.toLowerCase()));
    results.replaceChildren(...matches.map(([id, title, description]) => item(title, description, () => openPage(id), 'Page')));
    if (query) results.append(item(`Search chain: ${query}`, 'Look up a block height, address, or block / transaction / box / token ID.', () => search(query), 'Lookup'));
    dialog.querySelector('[data-count]').textContent = query ? `${results.children.length} options` : 'Jump to a page';
  }
  const open = () => {
    if (!canOpen() || dialog.open) return;
    previousFocus = document.activeElement;
    input.value = '';
    render();
    dialog.showModal();
    input.focus();
  };
  trigger.addEventListener('click', open);
  dialog.querySelector('[data-close]').onclick = () => dialog.close();
  dialog.addEventListener('close', () => { if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true }); });
  input.addEventListener('input', render);
  dialog.querySelector('form').onsubmit = e => { e.preventDefault(); results.querySelector('button')?.click(); };
  dialog.addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key)) return;
    const buttons = [...results.querySelectorAll('button')];
    if (!buttons.length) return;
    e.preventDefault();
    const current = buttons.indexOf(document.activeElement);
    const next = current < 0 ? (e.key === 'ArrowDown' ? 0 : buttons.length - 1) : (current + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next].focus();
  });
  return open;
}
