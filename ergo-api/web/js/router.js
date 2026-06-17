// Hash router for SPA sections. On each hash change it first asks the outgoing
// section whether it may leave (beforeLeave — e.g. the wallet vetoes navigation
// while a recovery phrase is on screen); if allowed, it toggles section
// visibility + sidebar aria-current and calls onEnter(section). A vetoed leave
// restores the previous hash, which re-fires hashchange — absorbed by the
// same-section guard.
export function startRouter(sections, onEnter, beforeLeave) {
  const valid = new Set(sections);
  let active = null;
  function resolve() {
    const s = location.hash.replace('#', '');
    return valid.has(s) ? s : sections[0];
  }
  function apply() {
    const s = resolve();
    if (s === active) return;
    if (active && beforeLeave && !beforeLeave(active)) {
      // Vetoed: restore the hash without re-running the switch (the resulting
      // hashchange resolves back to `active` and hits the guard above).
      if (location.hash.replace('#', '') !== active) location.hash = active;
      return;
    }
    active = s;
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
  return { current: () => active };
}
