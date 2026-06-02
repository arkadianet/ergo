// Minimal hash router for dashboard sections. Calls onEnter(section) and
// toggles section visibility + sidebar aria-current.
export function startRouter(sections, onEnter) {
  const valid = new Set(sections);
  function apply() {
    let s = location.hash.replace('#', '') || sections[0];
    if (!valid.has(s)) s = sections[0];
    for (const name of sections) {
      const el = document.getElementById(`section-${name}`);
      if (el) el.hidden = name !== s;
      const link = document.querySelector(`.side__link[data-section="${name}"]`);
      if (link) {
        if (name === s) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
    }
    onEnter(s);
  }
  window.addEventListener('hashchange', apply);
  apply();
  return { current: () => location.hash.replace('#', '') || sections[0] };
}
