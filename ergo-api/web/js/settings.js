// Settings: API key (session-only) + non-secret prefs (localStorage).
const KEY = 'ergo.apikey'; // sessionStorage — never persisted to disk
const PREFS = 'ergo.prefs'; // localStorage — theme/density/explorer
const defaults = { theme: 'dark', density: 'normal', explorer: '' };

export function getApiKey() {
  return sessionStorage.getItem(KEY) || '';
}
export function setApiKey(v) {
  if (v) sessionStorage.setItem(KEY, v);
  else sessionStorage.removeItem(KEY);
}
export function prefs() {
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(PREFS) || '{}') };
  } catch {
    return { ...defaults };
  }
}
export function setPref(k, v) {
  const p = prefs();
  p[k] = v;
  localStorage.setItem(PREFS, JSON.stringify(p));
  applyPrefs();
}
export function explorerTxUrl(id) {
  const e = prefs().explorer.trim();
  return e ? e.replace(/\/$/, '') + '/transactions/' + id : null;
}
export function applyPrefs() {
  const p = prefs();
  document.documentElement.className = `theme-${p.theme}`;
  document.body.classList.toggle('density-compact', p.density === 'compact');
}

export function initSettings(dialog, openBtn) {
  applyPrefs();
  const p = prefs();
  // Static template only — no untrusted interpolation. Field values are
  // assigned via the DOM below (.value is not parsed as HTML).
  const opts = (list) => list.map((v) => `<option>${v}</option>`).join('');
  dialog.innerHTML = `
    <form method="dialog" class="dialog__body">
      <h3 class="micro-label">Settings</h3>
      <label>API key
        <input id="set-key" type="password" autocomplete="off"></label>
      <label>Explorer URL (optional)
        <input id="set-exp" placeholder="https://explorer.ergoplatform.com"></label>
      <label>Theme
        <select id="set-theme">${opts(['dark', 'light', 'hc'])}</select></label>
      <label>Density
        <select id="set-den">${opts(['normal', 'compact'])}</select></label>
      <div class="dialog__actions">
        <button class="btn btn--primary" value="save" type="submit">Save</button>
        <button class="btn" value="cancel" type="submit">Close</button>
      </div>
    </form>`;
  dialog.querySelector('#set-key').value = getApiKey();
  dialog.querySelector('#set-exp').value = p.explorer;
  dialog.querySelector('#set-theme').value = p.theme;
  dialog.querySelector('#set-den').value = p.density;
  openBtn.addEventListener('click', () => dialog.showModal());
  dialog.addEventListener('close', () => {
    if (dialog.returnValue !== 'save') return;
    setApiKey(dialog.querySelector('#set-key').value.trim());
    setPref('explorer', dialog.querySelector('#set-exp').value.trim());
    setPref('theme', dialog.querySelector('#set-theme').value);
    setPref('density', dialog.querySelector('#set-den').value);
  });
}
