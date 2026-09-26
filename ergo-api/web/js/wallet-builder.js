import { TransactionSession, makeIntent, amount, integer, decimal } from './wallet-transaction.js';
import { tokenName, getTokenMeta } from './token-meta.js';
import { num, truncMiddle } from './format.js';

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
  }
  n.append(...kids); return n;
}
const button = (text, onclick, cls = '') => el('button', { type: 'button', class: `btn ${cls}`, text, onclick });
const label = (text, input) => el('label', { class: 'w-field' }, el('span', { class: 'w-label', text }), input);
const note = text => el('p', { class: 'wb-note', text });
const tokenLabel = id => tokenName(id) || `Token ${truncMiddle(id, 8, 6)}`;
const money = value => `${decimal(value)} ERG`;
const line = (title, value) => el('div', { class: 'wb-fact' }, el('span', { text: title }), el('strong', { text: value }));

export function createWalletBuilder(host, { api, active, onBusy, onSent }) {
  let balance = null, status = null, disposed = false, dirty = false;
  const session = new TransactionSession(api, () => !disposed && !!status?.isUnlocked && active());
  const recipients = [];
  const error = el('div', { class: 'banner banner--err', role: 'alert', hidden: true });
  const rows = el('div', { class: 'wb-recipients' });
  const review = el('aside', { class: 'wb-review', 'aria-label': 'Transaction review', tabindex: '-1' });
  const fee = el('input', { class: 'input', inputmode: 'decimal', value: '0.001', required: true });
  const rewards = el('input', { type: 'checkbox' });
  const build = button('Build unsigned transaction', buildDraft, 'btn--primary');
  const fields = el('fieldset', { class: 'wb-fields' });
  const available = el('span', { class: 'wb-note' });
  const change = el('code', { class: 'wb-address' });
  fields.append(
    el('div', { class: 'wb-heading' }, el('h3', { text: 'Where should it go?' }), available), rows,
    button('+ Add recipient', () => { addRecipient(); invalidate(); }),
    el('div', { class: 'wb-options' }, label('Network fee · ERG', fee), note('The node selects inputs and calculates change. Any dust added to the fee is shown in the review.')),
    el('details', { class: 'wb-advanced' }, el('summary', { text: 'Change & mining rewards' }),
      note('Change returns to this tracked address:'), change,
      el('label', { class: 'wb-check' }, rewards, el('span', { text: 'Allow spending mining reward boxes, including their required re-emission payment.' }))),
    error, el('div', { class: 'wb-actions' }, build, button('Clear draft', () => {
      if (dirty && !window.confirm(session.signed ? 'A signed transaction may already be in the network. Check its ID before starting another payment. Clear this draft?' : 'Clear all recipients and this unsigned preview?')) return;
      reset();
    })), note('Building does not sign or send. You will review the actual plan before a separate confirmation.'),
  );
  fields.addEventListener('input', invalidate);
  host.replaceChildren(el('div', { class: 'wb-layout' }, fields, review));
  function invalidate() {
    // All editable controls are disabled during a network operation.
    dirty = true; session.invalidate(); error.hidden = true; emptyReview();
  }
  function emptyReview() {
    review.replaceChildren(el('div', { class: 'wb-eyebrow', text: '01 / COMPOSE → 02 / REVIEW' }),
      el('h3', { text: 'Know exactly what leaves.' }),
      note('Build a transaction to inspect its selected inputs, recipient amounts, actual fee, and change.'),
      el('div', { class: 'wb-review-placeholder' },
        line('Payments', `${recipients.length} recipient${recipients.length === 1 ? '' : 's'}`),
        line('Input selection', 'Automatic'), line('Signing', 'Not started')),
      note('Tokens stay in your wallet unless included in a payment. Mining reward spending requires explicit opt-in.'));
  }
  function setBusy(busy) { fields.disabled = busy || !status?.isUnlocked; build.textContent = busy ? 'Working…' : 'Build unsigned transaction'; onBusy(busy); }
  function showError(e) { error.textContent = e.message; error.hidden = false; }
  function addRecipient() {
    const address = el('input', { class: 'input wb-address-input', placeholder: 'Ergo P2PK address', autocomplete: 'off', spellcheck: 'false', required: true });
    const value = el('input', { class: 'input', placeholder: '0.00', inputmode: 'decimal', required: true });
    const tokenRows = el('div', { class: 'wb-token-rows' });
    const picker = el('div', { class: 'wb-picker', hidden: true });
    const heading = el('strong');
    const recipient = { address, value, tokens: [], heading };
    const remove = button('Remove', () => {
      recipients.splice(recipients.indexOf(recipient), 1); card.remove();
      if (!recipients.length) addRecipient();
      renumber(); invalidate();
    }, 'btn--sm');
    const card = el('section', { class: 'wb-recipient' }, el('div', { class: 'wb-heading' }, heading, remove),
      label('Recipient address', address), label('Amount · ERG', value), tokenRows,
      button('+ Add token', () => { picker.hidden = !picker.hidden; if (!picker.hidden) showPicker(); }, 'btn--sm'), picker);
    recipient.addToken = id => {
      if (session.busy || session.signed) return;
      if (recipient.tokens.some(t => t.tokenId === id)) return;
      const meta = getTokenMeta(id);
      const input = el('input', { class: 'input', inputmode: 'decimal', placeholder: '0', required: true, 'aria-label': `${tokenLabel(id)} amount` });
      const t = { tokenId: id, decimals: meta?.decimals || 0, input };
      const tokenRow = el('div', { class: 'wb-token-row' },
        el('div', {}, el('strong', { text: tokenLabel(id) }), el('code', { text: truncMiddle(id, 14, 10), title: id }),
          el('small', { text: meta ? `${t.decimals} decimal places` : 'Metadata unavailable · raw units' })),
        input, button('Max', () => {
          try {
            let left = integer(balance.assets.find(a => a.tokenId === id)?.amount || '0');
            for (const r of recipients) for (const other of r.tokens) if (other !== t && other.tokenId === id && other.input.value.trim()) left -= integer(amount(other.input.value, other.decimals));
            if (left <= 0n) throw new Error('No units remain after the other recipients.');
            input.value = decimal(left.toString(), t.decimals); invalidate();
          } catch (e) { showError(e); }
        }, 'btn--sm'), button('×', () => { recipient.tokens.splice(recipient.tokens.indexOf(t), 1); tokenRow.remove(); invalidate(); }, 'btn--sm'));
      tokenRow.lastChild.setAttribute('aria-label', `Remove ${tokenLabel(id)}`);
      recipient.tokens.push(t); tokenRows.append(tokenRow); picker.hidden = true; invalidate(); input.focus();
    };
    function showPicker() {
      const search = el('input', { class: 'input', type: 'search', placeholder: 'Search token name or ID', 'aria-label': 'Find a token to send' });
      const results = el('div', { class: 'wb-token-results' });
      const render = () => {
        const query = search.value.trim().toLowerCase();
        const matches = (balance?.assets || []).filter(a => !recipient.tokens.some(t => t.tokenId === a.tokenId) && `${tokenLabel(a.tokenId)} ${a.tokenId}`.toLowerCase().includes(query));
        results.replaceChildren(...matches.slice(0, 10).map(a => {
          const b = button('', () => recipient.addToken(a.tokenId), 'wb-token-choice');
          b.append(el('span', { text: tokenLabel(a.tokenId) }), el('code', { text: truncMiddle(a.tokenId, 10, 8) }), el('small', { text: decimal(a.amount, getTokenMeta(a.tokenId)?.decimals || 0) }));
          return b;
        }));
        if (!matches.length) results.append(note('No matching tokens in this wallet.'));
        if (matches.length > 10) results.append(note(`${matches.length} matches · keep typing to narrow the list.`));
      };
      search.addEventListener('input', e => { e.stopPropagation(); render(); });
      picker.replaceChildren(search, results); render(); search.focus();
    }
    recipients.push(recipient); rows.append(card); renumber();
    return recipient;
  }
  function renumber() { recipients.forEach((r, i) => { r.heading.textContent = `Recipient ${String(i + 1).padStart(2, '0')}`; }); }
  function reset() { if (session.busy) return; session.invalidate(); fields.disabled = !status?.isUnlocked; rows.replaceChildren(); recipients.length = 0; fee.value = '0.001'; rewards.checked = false; error.hidden = true; addRecipient(); dirty = false; emptyReview(); }
  async function buildDraft() {
    if (!status?.isUnlocked || session.busy) return;
    error.hidden = true;
    try {
      const intent = makeIntent(recipients.map(r => ({ address: r.address.value, erg: r.value.value, tokens: r.tokens.map(t => ({ ...t, amount: t.input.value })) })), fee.value, balance, status.changeAddress, rewards.checked);
      setBusy(true);
      emptyReview();
      await session.build(intent);
      if (disposed) return;
      renderReview(); review.focus();
    } catch (e) { if (!disposed) showError(e); }
    finally { if (!disposed) setBusy(false); else onBusy(false); }
  }
  function renderReview() {
    const p = session.plan, intent = session.intent;
    const paymentTotal = intent.outputs.reduce((n, o) => n + integer(o.value), 0n);
    const changeTotal = p.changeOutputs.reduce((n, o) => n + integer(o.nanoErg), 0n);
    const burn = p.reemissionBurn?.nanoErgRouted || '0';
    const total = paymentTotal + integer(p.fee) + integer(burn);
    const confirmed = el('input', { type: 'checkbox' });
    const final = button('Sign & broadcast', confirm, 'btn--primary'); final.disabled = true;
    const feedback = el('div', { role: 'status', class: 'wb-note' });
    confirmed.addEventListener('change', () => { final.disabled = !confirmed.checked; });
    review.replaceChildren(el('div', { class: 'wb-eyebrow', text: '02 / REVIEW · UNSIGNED' }),
      el('h3', { text: 'Your transaction is built.' }), note('Nothing has been signed or sent.'),
      el('div', { class: 'wb-total' }, el('span', { text: p.reemissionBurn ? 'Payments + fee + re-emission' : 'Payments + fee' }), el('strong', { text: money(total.toString()) })),
      ...intent.outputs.map((o, i) => el('div', { class: 'wb-review-payment' }, line(`Recipient ${i + 1}`, money(o.value)),
        el('code', { class: 'wb-address', text: o.address }),
        ...o.assets.map(a => el('div', {}, line(tokenLabel(a.tokenId), `${a.amount} raw unit${a.amount === '1' ? '' : 's'}`), el('code', { class: 'wb-address', text: a.tokenId }))))),
      line('Actual network fee', money(p.fee)),
      ...(p.fee !== intent.fee ? [note('The node added dust change to your requested fee. Review the actual amount above.')] : []),
      ...(p.reemissionBurn ? [line('Required re-emission payment', money(burn)), note(`${p.reemissionBurn.tokensBurned} re-emission token units will be burned.`)] : []),
      line('Returns as change', money(changeTotal.toString())),
      el('code', { class: 'wb-address', text: intent.changeAddress }),
      el('details', { class: 'wb-details' }, el('summary', { text: `${p.inputsSelected.length} input${p.inputsSelected.length === 1 ? '' : 's'} · ${p.changeOutputs.length} change output${p.changeOutputs.length === 1 ? '' : 's'} · height ${num(p.asOf)}` }),
        ...p.inputsSelected.map(i => el('div', { class: 'wb-detail-row' }, el('code', { class: 'wb-address', text: i.boxId }), note(`${money(i.value)} · ${i.assets.length} token types`))),
        ...p.changeOutputs.map((c, i) => el('div', { class: 'wb-detail-row' }, line(`Change output ${i + 1}`, money(c.nanoErg)),
          ...c.assets.map(a => el('div', {}, el('code', { class: 'wb-address', text: a.tokenId }), note(`${a.amount} raw units returned`)))))),
      button('Download unsigned transaction', () => {
        const blob = new Blob([JSON.stringify({ unsignedTransaction: p.unsignedTransaction, intent, plan: p }, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob), a = el('a', { href: url, download: 'ergo-unsigned-transaction.json' });
        a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      }, 'btn--sm'),
      el('label', { class: 'wb-check wb-confirm' }, confirmed, el('span', { text: 'I have checked every recipient, token amount, fee, and change address.' })),
      final, feedback,
    );
    async function confirm() {
      if (!confirmed.checked || session.busy) return;
      setBusy(true); final.disabled = true; confirmed.disabled = true;
      feedback.textContent = session.signed ? 'Retrying the same signed transaction…' : 'Signing the reviewed transaction, then broadcasting…';
      try {
        const sent = await session.confirm();
        if (disposed) return;
        dirty = false;
        review.replaceChildren(el('div', { class: 'wb-eyebrow', text: 'SUBMITTED TO YOUR NODE' }), el('h3', { text: 'Waiting for confirmation' }),
          note('Accepted by the node. Inclusion in a block is still pending.'),
          el('a', { class: 'wb-address', href: `#explorer/tx/${sent.txId}`, text: sent.txId }), button('New transaction', reset));
        fields.disabled = true; onSent();
      } catch (e) {
        if (disposed) return;
        feedback.textContent = session.signed ? `${e.message} Check transaction ${session.txId} in the explorer. Retrying resubmits only these same signed bytes.` : e.message;
        final.textContent = session.signed ? 'Retry same transaction' : 'Sign & broadcast';
        confirmed.checked = false; confirmed.disabled = false;
        if (session.signed && !review.querySelector('[data-abandon]')) {
          const abandon = button('Discard local draft', () => {
            if (window.confirm('The transaction may already be in the network. Check its ID before making another payment. Discard this local draft?')) reset();
          }, 'btn--sm');
          abandon.setAttribute('data-abandon', ''); review.append(abandon);
        }
      } finally {
        onBusy(false);
        // A signed/uncertain submission must not silently become a different payment.
        if (!disposed && !session.signed) setBusy(false);
        else if (!disposed) { build.textContent = 'Build unsigned transaction'; }
      }
    }
  }
  reset();
  return {
    update(nextBalance, nextStatus) {
      if (status && (status.changeAddress !== nextStatus.changeAddress || status.isUnlocked !== nextStatus.isUnlocked)) session.invalidate();
      const accessChanged = status && (status.changeAddress !== nextStatus.changeAddress || status.isUnlocked !== nextStatus.isUnlocked);
      balance = nextBalance; status = nextStatus;
      available.textContent = balance ? `${money(balance.nanoErg.available)} available` : 'Balance unavailable';
      change.textContent = status?.changeAddress || 'No change address';
      fields.disabled = session.busy || !status?.isUnlocked || !!session.signed;
      if (accessChanged) emptyReview();
    },
    addToken(id) { const r = recipients.at(-1); r.addToken(id); },
    isDirty: () => dirty,
    dispose() { disposed = true; session.invalidate(); host.replaceChildren(); },
  };
}
