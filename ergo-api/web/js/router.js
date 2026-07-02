// Hash router for SPA sections. On each hash change it first asks the outgoing
// section whether it may leave (beforeLeave — e.g. the wallet vetoes navigation
// while a recovery phrase is on screen); if allowed, it toggles section
// visibility + sidebar aria-current and calls onEnter(section, tail). A vetoed
// leave restores the previous hash, which re-fires hashchange — absorbed by the
// same-route guard.
//
// Hashes may carry a sub-path after the section name (`#explorer/tx/<id>`):
// the segment before the first `/` picks the section, the rest is the `tail`
// passed verbatim to onEnter. Flat hashes (`#peers`) have an empty tail, so
// tail-less sections behave exactly as before. A tail-only change (same
// section, different entity) does NOT re-run the section switch or the
// beforeLeave veto — it just re-fires onEnter so the section can re-route.
export function startRouter(sections, onEnter, beforeLeave) {
  const valid = new Set(sections);
  let active = null;
  let activeTail = null;
  function resolve() {
    const raw = location.hash.replace(/^#/, '');
    const slash = raw.indexOf('/');
    const head = slash < 0 ? raw : raw.slice(0, slash);
    if (!valid.has(head)) return { section: sections[0], tail: '' };
    return { section: head, tail: slash < 0 ? '' : raw.slice(slash + 1) };
  }
  function apply() {
    const { section: s, tail } = resolve();
    if (s === active && tail === activeTail) return;
    if (s !== active && active && beforeLeave && !beforeLeave(active)) {
      // Vetoed: restore the hash without re-running the switch (the resulting
      // hashchange resolves back to `active` and hits the guard above).
      const restore = activeTail ? `${active}/${activeTail}` : active;
      if (location.hash.replace(/^#/, '') !== restore) location.hash = restore;
      return;
    }
    active = s;
    activeTail = tail;
    for (const name of sections) {
      const el = document.getElementById(`section-${name}`);
      if (el) el.hidden = name !== s;
      const link = document.querySelector(`.side__link[data-section="${name}"]`);
      if (link) {
        if (name === s) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
    }
    onEnter(s, tail);
  }
  window.addEventListener('hashchange', apply);
  apply();
  return { current: () => active };
}
