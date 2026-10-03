import { getApiKey, report, subscribe } from './auth.js';

export const SPECTRUM_N2T_TREE_HASH = '99f30ad579a2c98ad31b432676627fcd9e303d43c06e898725f6155d8ac40aa9';
const terminal = new Set(['conflicted', 'cancelled', 'expired', 'failed']);
export const canCancelSwap = (item) => !terminal.has(item.state) || (item.state === 'conflicted' && Boolean(item.txId));
const decimal = (text) => {
  if (!/^[1-9][0-9]*$/.test(text) || BigInt(text) > 9223372036854775807n) throw new Error('Amounts must be positive whole raw units within the Ergo Long limit.');
  return text;
};

export function swapDraft(values) {
  const id = (value) => {
    const result = value.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(result)) throw new Error('Pool and funding IDs must contain 64 hexadecimal characters.');
    return result;
  };
  const fundingBoxIds = values.funding.trim().split(/[\s,]+/).filter(Boolean).map(id);
  if (!fundingBoxIds.length || fundingBoxIds.length > 32 || new Set(fundingBoxIds).size !== fundingBoxIds.length) throw new Error('Pin 1–32 distinct owned funding box IDs.');
  const height = (name) => {
    if (!/^(0|[1-9][0-9]*)$/.test(values[name])) throw new Error('Heights and attempts must be whole numbers.');
    const result = Number(values[name]);
    if (!Number.isSafeInteger(result) || result > 4294967295) throw new Error('Height exceeds the supported range.');
    return result;
  };
  const inputAmount = decimal(values.input.trim()), maxInputAmount = decimal(values.maximum.trim());
  if (BigInt(inputAmount) > BigInt(maxInputAmount)) throw new Error('Exact trade input exceeds your maximum input.');
  const notBeforeHeight = height('start'), expiresAtHeight = height('expiry'), maxAttempts = height('attempts');
  const maxSlippageBasisPoints = height('slippage');
  if (expiresAtHeight <= notBeforeHeight || maxAttempts < 1 || maxAttempts > 100 || maxSlippageBasisPoints > 10000) throw new Error('Use a later deadline, 1–100 attempts and 0–10,000 slippage basis points.');
  if (!values.label.trim() || new TextEncoder().encode(values.label.trim()).length > 160 || !values.receiver.trim()) throw new Error('Enter a short label and tracked receiving address.');
  if (!['ergToToken', 'tokenToErg'].includes(values.direction)) throw new Error('Choose a supported swap direction.');
  return {
    label: values.label.trim(), poolBoxId: id(values.pool), poolNft: id(values.nft), poolTreeHash: SPECTRUM_N2T_TREE_HASH,
    fundingBoxIds, receivingAddress: values.receiver.trim(), direction: values.direction,
    inputAmount, maxInputAmount, minOutputAmount: decimal(values.minimum.trim()), approvedQuoteOutput: decimal(values.quote || '1'),
    maxSlippageBasisPoints, notBeforeHeight, expiresAtHeight, maxAttempts,
  };
}

export function effectiveSwapMinimum(request) {
  const retained = BigInt(request.approvedQuoteOutput) * BigInt(10000 - request.maxSlippageBasisPoints) / 10000n;
  const minimum = BigInt(request.minOutputAmount);
  return (minimum > retained ? minimum : retained).toString();
}

async function request(path, method = 'GET', body = null) {
  const key = getApiKey();
  if (!key) return { ok: false, detail: 'Authorize to manage private swaps.' };
  try {
    const response = await fetch('/api/v1/wallet/mining-swaps' + path, {
      method, cache: 'no-store', headers: { api_key: key, 'content-type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(12000),
    });
    const data = await response.json().catch(() => null);
    report(response.status, true, key, data?.reason);
    if (key !== getApiKey()) return { ok: false, stale: true };
    return { ok: response.ok, data, detail: data?.detail ?? data?.reason ?? `Request failed (${response.status}).` };
  } catch { return { ok: false, detail: 'Could not reach the bounded swap API.' }; }
}

export function mountMiningSwaps(container) {
  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.innerHTML = `
    <div class="panel__head"><h3 class="panel__title">Mine a private direct swap</h3></div>
    <div class="panel__body">
      <p>Approve a bounded swap from your node wallet against a canonical Spectrum ERG/token pool. If the pool is spent, the node retires its previous private transaction and signs a fresh one within your price limits.</p>
      <p class="muted">Amounts use raw token units and nanoERG. Pin confirmed owned funding boxes and a receiving address tracked by this wallet. Each funding box keeps its registers and unrelated tokens. Mining has zero transaction fee; storage dust stays in your wallet.</p>
      <p data-swap-status role="status"></p>
      <form data-swap-form>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
          <label>Label<input name="label" maxlength="160" required></label>
          <label>Current pool box ID<input name="pool" spellcheck="false" required></label>
          <label>Pool NFT ID<input name="nft" spellcheck="false" required></label>
          <label>Tracked receiving address<input name="receiver" spellcheck="false" required></label>
          <label>Direction<select name="direction"><option value="ergToToken">ERG → token</option><option value="tokenToErg">Token → ERG</option></select></label>
          <label>Exact trade input (raw units)<input name="input" inputmode="numeric" required></label>
          <label>Maximum trade input (raw units)<input name="maximum" inputmode="numeric" required></label>
          <label>Minimum received (raw units)<input name="minimum" inputmode="numeric" required></label>
          <label>Maximum slippage (basis points; 100 = 1%)<input name="slippage" type="number" min="0" max="10000" value="100" required></label>
          <label>Start at applied height<input name="start" type="number" min="0" required></label>
          <label>Last allowed block height<input name="expiry" type="number" min="1" required></label>
          <label>Maximum attempts<input name="attempts" type="number" min="1" max="100" value="3" required></label>
        </div>
        <label>Pinned owned funding box IDs<textarea name="funding" rows="3" spellcheck="false" required></textarea></label>
        <p class="muted">The deadline must be within 7,200 blocks of approval. Automatic refresh requires this node wallet to be unlocked and retained applied block history to follow the pinned pool NFT. Android signatures remain fixed to their original transaction.</p>
        <button class="btn" type="submit">Preview quote and transaction</button>
        <button class="btn btn--primary" type="button" data-swap-approve disabled>Approve private swap intent</button>
      </form>
      <pre data-swap-preview hidden style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
      <button class="btn" type="button" data-swap-reload>Refresh intents</button>
      <div data-swap-list></div>
    </div>`;
  container.append(panel);
  const form = panel.querySelector('[data-swap-form]'), status = panel.querySelector('[data-swap-status]');
  const output = panel.querySelector('[data-swap-preview]'), list = panel.querySelector('[data-swap-list]');
  const approve = panel.querySelector('[data-swap-approve]');
  let approvedDraft = null, unsubscribe = null, accessKey = null, walletUnlocked = false, authorized = false, generation = 0, active = false, busy = false;
  const clearComposition = () => {
    generation++; approvedDraft = null; approve.disabled = true; form.reset(); output.textContent = ''; output.hidden = true;
  };
  const scrub = () => { clearComposition(); list.replaceChildren(); };
  const update = (walletStatus) => {
    const unlocked = Boolean(walletStatus?.isInitialized && walletStatus?.isUnlocked);
    if (!unlocked && walletUnlocked) clearComposition();
    walletUnlocked = unlocked;
    form.hidden = !authorized || !walletUnlocked;
    if (authorized && !walletUnlocked) status.textContent = 'Unlock the node wallet to preview and approve swaps. Existing intents and cancellation remain available.';
  };
  const refresh = async () => {
    if (!active || busy || !authorized || !getApiKey()) return;
    const stamp = generation, response = await request('');
    if (!active || stamp !== generation || response.stale) return;
    if (!response.ok) { status.textContent = response.detail; return; }
    list.replaceChildren();
    for (const item of response.data?.items ?? []) {
      const row = document.createElement('div'); row.className = 'w-row';
      const text = document.createElement('p');
      text.textContent = `#${item.id} ${item.request.label}: ${item.state} · generation ${item.generation} · attempts ${item.attempts}/${item.request.maxAttempts}${item.quotedOutputAmount ? ' · output ' + item.quotedOutputAmount : ''}${item.detail ? ' · ' + item.detail : ''}`;
      row.append(text);
      if (canCancelSwap(item)) {
        const cancel = document.createElement('button'); cancel.className = 'btn'; cancel.textContent = item.state === 'mined' ? 'Stop future intent retries' : 'Cancel and retire private work';
        cancel.addEventListener('click', async () => {
          cancel.disabled = true;
          const result = await request('/' + encodeURIComponent(item.id) + '/cancel', 'POST', {});
          if (result.stale || !active) return;
          status.textContent = result.ok ? `Intent #${item.id}: ${result.data.state}.` : result.detail;
          await refresh();
        }); row.append(cancel);
      }
      list.append(row);
    }
  };
  form.addEventListener('input', () => { generation++; approvedDraft = null; approve.disabled = true; output.hidden = true; });
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (busy || !authorized || !walletUnlocked) return;
    approvedDraft = null; approve.disabled = true; output.textContent = ''; output.hidden = true;
    try {
      const draft = swapDraft(Object.fromEntries(new FormData(form))), stamp = generation;
      busy = true; status.textContent = 'Checking pinned pool and owned funding…';
      const result = await request('/preview', 'POST', draft);
      if (!active || stamp !== generation || result.stale) return;
      if (!result.ok) { status.textContent = result.detail; return; }
      approvedDraft = { ...draft, approvedQuoteOutput: result.data.quotedOutputAmount };
      const minimum = effectiveSwapMinimum(approvedDraft);
      output.textContent = `Receive quote: ${result.data.quotedOutputAmount} raw units\nRefresh minimum: ${minimum} raw units\nTrade input: ${draft.inputAmount} raw units\nPool: ${result.data.poolBoxId}\nTrade token: ${result.data.tradeTokenId}\nSnapshot height: ${result.data.snapshotHeight}\nDeadline: block ${draft.expiresAtHeight}\n\nUnsigned transaction:\n${result.data.unsignedTransaction.bytes}`;
      output.hidden = false; approve.disabled = false; status.textContent = 'Review this quote and the pinned transaction, then approve the bounded intent.';
    } catch (error) { status.textContent = error.message; }
    finally { busy = false; }
  });
  approve.addEventListener('click', async () => {
    if (!approvedDraft || busy || !authorized || !walletUnlocked) return;
    busy = true; approve.disabled = true; const stamp = generation;
    const result = await request('', 'POST', approvedDraft);
    busy = false;
    if (!active || stamp !== generation || result.stale) return;
    status.textContent = result.ok ? `Intent #${result.data.id} approved. Unlock the node wallet when it is ready to sign.` : result.detail;
    approvedDraft = null; output.hidden = true; await refresh();
  });
  panel.querySelector('[data-swap-reload]').addEventListener('click', refresh);
  return {
    refresh,
    update,
    onShow() {
      active = true;
      unsubscribe?.(); unsubscribe = subscribe((authState) => {
        const key = getApiKey(), permitted = authState === 'authorized' && Boolean(key);
        if (accessKey !== key || !permitted) { scrub(); accessKey = key; }
        authorized = permitted;
        form.hidden = !authorized || !walletUnlocked; list.hidden = !authorized;
        if (!authorized) status.textContent = 'Authorize to manage private swap intents.';
        else if (!walletUnlocked) status.textContent = 'Unlock the node wallet to preview and approve swaps. Existing intents and cancellation remain available.';
        void refresh();
      });
    },
    onHide() { active = false; authorized = false; walletUnlocked = false; unsubscribe?.(); unsubscribe = null; scrub(); },
  };
}
