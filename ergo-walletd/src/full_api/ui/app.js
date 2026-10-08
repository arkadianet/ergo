import { initAuth } from './auth.js';
import * as wallet from './wallet.js';

initAuth(document.querySelector('#auth-chip'), document.querySelector('#auth-dialog'));
wallet.mount(document.querySelector('#section-wallet'));
wallet.onShow();
const poll = setInterval(() => wallet.onSlow(), 4000);
window.addEventListener('beforeunload', (event) => {
  if (!wallet.canLeave()) {
    event.preventDefault();
    event.returnValue = '';
  }
});
window.addEventListener('pagehide', () => {
  clearInterval(poll);
  wallet.onHide();
});
window.addEventListener('pageshow', (event) => {
  // A restored page must establish a fresh auth subscription and polling loop.
  if (event.persisted) window.location.reload();
});
