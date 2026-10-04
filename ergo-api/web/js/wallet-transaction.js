// Exact amounts and the wallet's build → review → explicit sign/submit lifecycle.
// No DOM, storage, automatic submission, or retries. Native DTOs use strings.
const U64 = (1n << 64n) - 1n;
export function integer(value) {
  if (typeof value !== 'string' || !/^\d+$/.test(value) || BigInt(value) > U64) throw new Error('The node returned an invalid exact amount.');
  return BigInt(value);
}
export function amount(value, decimals = 9) {
  const s = String(value).trim();
  if (!/^\d+(\.\d+)?$/.test(s) || !Number.isInteger(decimals) || decimals < 0 || decimals > 19) throw new Error('Enter a positive decimal amount.');
  const [whole, fraction = ''] = s.split('.');
  if (fraction.length > decimals) throw new Error(`Use at most ${decimals} decimal places.`);
  const n = BigInt(whole + fraction.padEnd(decimals, '0'));
  if (n <= 0n || n > U64) throw new Error('Amount must be positive and within the supported range.');
  return n.toString();
}
export function decimal(value, decimals = 9) {
  const n = integer(value).toString().padStart(decimals + 1, '0');
  if (!decimals) return n;
  return (n.slice(0, -decimals) + '.' + n.slice(-decimals)).replace(/\.?0+$/, '');
}
export function makeIntent(recipients, fee, balance, changeAddress, allowReemissionSpend = false) {
  if (!balance) throw new Error('Wait for the wallet balance before building.');
  const available = new Map(balance.assets.map(a => [a.tokenId, integer(a.amount)]));
  const used = new Map();
  let total = 0n;
  if (!recipients.length) throw new Error('Add a recipient.');
  const outputs = recipients.map((r, index) => {
    const prefix = `Recipient ${index + 1}: `;
    const address = r.address.trim();
    if (!/^[1-9A-HJ-NP-Za-km-z]{30,120}$/.test(address)) throw new Error(prefix + 'enter a valid Ergo address.');
    let value;
    try { value = amount(r.erg); } catch (e) { throw new Error(prefix + e.message); }
    total += integer(value);
    const seen = new Set();
    const assets = r.tokens.map(t => {
      if (!/^[a-f0-9]{64}$/.test(t.tokenId) || seen.has(t.tokenId)) throw new Error(prefix + 'choose each token only once.');
      seen.add(t.tokenId);
      let raw;
      try { raw = amount(t.amount, t.decimals); } catch (e) { throw new Error(prefix + 'token amount: ' + e.message); }
      const sum = (used.get(t.tokenId) || 0n) + integer(raw);
      if (sum > (available.get(t.tokenId) || 0n)) throw new Error(prefix + 'token amounts across recipients exceed your holdings.');
      used.set(t.tokenId, sum);
      return { tokenId: t.tokenId, amount: raw };
    });
    return { type: 'payment', address, value, assets };
  });
  const feeRaw = amount(fee);
  if (total + integer(feeRaw) > integer(balance.nanoErg.available)) throw new Error('Payments and fee exceed your available ERG.');
  if (!changeAddress) throw new Error('A tracked change address is required.');
  return { outputs, fee: feeRaw, changeAddress, inputs: { type: 'auto' }, allowReemissionSpend, allowTokenBurn: false };
}
function checkBytes(tx) {
  if (tx?.type !== 'bytes' || !/^(?:[a-f0-9]{2})+$/i.test(tx.bytes)) throw new Error('The node did not return valid transaction bytes.');
}
export function checkPlan(intent, plan) {
  checkBytes(plan?.unsignedTransaction);
  if (!Array.isArray(plan.inputsSelected) || !plan.inputsSelected.length || !Array.isArray(plan.changeOutputs)) throw new Error('The transaction plan is incomplete.');
  const tokens = new Map();
  const addTokens = (assets, sign) => {
    for (const a of assets) tokens.set(a.tokenId, (tokens.get(a.tokenId) || 0n) + sign * integer(a.amount));
  };
  const ids = new Set();
  let incoming = 0n, outgoing = integer(plan.fee);
  if (outgoing < integer(intent.fee)) throw new Error('The built fee is below the requested fee.');
  for (const input of plan.inputsSelected) {
    if (!/^[a-f0-9]{64}$/.test(input.boxId) || ids.has(input.boxId)) throw new Error('The selected inputs are invalid.');
    ids.add(input.boxId); incoming += integer(input.value); addTokens(input.assets, 1n);
  }
  for (const output of intent.outputs) { outgoing += integer(output.value); addTokens(output.assets, -1n); }
  for (const change of plan.changeOutputs) { outgoing += integer(change.nanoErg); addTokens(change.assets, -1n); }
  if (plan.reemissionBurn) {
    if (!intent.allowReemissionSpend) throw new Error('The build unexpectedly spends re-emission reserves.');
    outgoing += integer(plan.reemissionBurn.nanoErgRouted);
    addTokens([{ tokenId: plan.reemissionBurn.tokenId, amount: plan.reemissionBurn.tokensBurned }], -1n);
  }
  if (incoming !== outgoing || [...tokens.values()].some(v => v !== 0n)) throw new Error('The transaction plan does not balance. Build again before signing.');
  return plan;
}
function result(res) {
  if (!res?.ok) throw new Error(res?.data?.detail || res?.reason || 'The node could not complete the request.');
  return res.data;
}
export class TransactionSession {
  constructor(api, active = () => true) {
    this.api = api; this.active = active; this.version = 0; this.busy = false;
    this.plan = null; this.intent = null; this.signed = null; this.txId = null;
  }
  invalidate() { this.version++; this.plan = this.intent = this.signed = this.txId = null; }
  async build(intent) {
    if (this.busy) throw new Error('A wallet operation is already in progress.');
    this.invalidate(); this.busy = true;
    const version = this.version, snapshot = structuredClone(intent);
    try {
      const plan = result(await this.api.build(snapshot));
      if (!this.active() || version !== this.version) throw new Error('Draft or wallet access changed. Build again.');
      checkPlan(snapshot, plan);
      this.intent = snapshot; this.plan = structuredClone(plan);
      return this.plan;
    } finally { this.busy = false; }
  }
  // Called only by the final explicit confirmation button. Never rebuilds:
  // signatures bind to the exact bytes returned by the reviewed build.
  async confirm() {
    if (this.busy || !this.plan || !this.active()) throw new Error('Build and review a transaction first.');
    this.busy = true;
    const version = this.version;
    const current = () => this.active() && version === this.version;
    try {
      if (!this.signed) {
        const status = result(await this.api.status());
        if (!status.isUnlocked || !current()) throw new Error('Wallet access changed. Unlock and build again.');
        const signed = result(await this.api.sign(structuredClone(this.plan.unsignedTransaction)));
        if (!current()) throw new Error('Wallet access changed. Nothing was broadcast by this page.');
        checkBytes(signed.signedTransaction);
        if (!/^[a-f0-9]{64}$/.test(signed.txId)) throw new Error('The signed transaction ID is invalid.');
        this.signed = structuredClone(signed.signedTransaction); this.txId = signed.txId;
      }
      if (!current()) throw new Error('Wallet access changed.');
      const sent = result(await this.api.submitSigned(structuredClone(this.signed)));
      if (!sent.accepted || sent.txId !== this.txId) throw new Error('Submission outcome is uncertain. Check the transaction ID before retrying.');
      return sent;
    } finally { this.busy = false; }
  }
}
