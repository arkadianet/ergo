// Settings: non-secret prefs (localStorage). The api_key is NOT here anymore —
// it lives in auth.js (the shell Authorize chip). Re-exported below so existing
// importers keep working during the migration.
export { getApiKey, setApiKey } from './auth.js';

const PREFS = 'ergo.prefs'; // localStorage — theme/density
// The old `explorer` external-URL pref (and its never-wired explorerTxUrl
// helper) was removed when the in-app Explorer section landed — a dead field
// named identically to a real section was pure confusion. A stale `explorer`
// key in stored prefs is harmless: defaults-merge just ignores it.
const defaults = { theme: 'dark', density: 'normal' };

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
  const opts = (list) => list.map(([value, label]) => `<option value="${value}">${label}</option>`).join('');
  dialog.innerHTML = `
    <form method="dialog" class="dialog__body">
      <h2 class="panel__title">Workspace appearance</h2>
      <p class="settings-help">Choose the look and spacing that suit your screen.</p>
      <label>Theme
        <select id="set-theme">${opts([['dark', 'Graphite'], ['light', 'Light'], ['hc', 'High contrast']])}</select></label>
      <label>Density
        <select id="set-den" aria-describedby="density-help">${opts([['normal', 'Comfortable'], ['compact', 'Compact']])}</select></label>
      <p class="settings-help" id="density-help">Compact reduces spacing to show more data. Browser zoom remains under your control.</p>
      <div class="dialog__actions">
        <button class="btn btn--primary" value="save" type="submit">Save</button>
        <button class="btn" value="cancel" type="submit">Cancel</button>
      </div>
    </form>`;
  dialog.querySelector('#set-theme').value = p.theme;
  dialog.querySelector('#set-den').value = p.density;
  openBtn.addEventListener('click', () => {
    const current = prefs();
    dialog.querySelector('#set-theme').value = current.theme;
    dialog.querySelector('#set-den').value = current.density;
    dialog.showModal();
  });
  dialog.addEventListener('close', () => {
    if (dialog.returnValue !== 'save') return;
    setPref('theme', dialog.querySelector('#set-theme').value);
    setPref('density', dialog.querySelector('#set-den').value);
  });
}
