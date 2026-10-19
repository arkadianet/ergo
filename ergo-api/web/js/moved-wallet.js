// Wallet page. The node hosts no wallet: the wallet daemon, `ergo-walletd`,
// holds the keys and serves its own wallet page. The public `GET /wallet/ui`
// answers `410 wallet_moved` with `[wallet] daemon_address`, which this page
// turns into a link, beside the steps that move an earlier release's wallet.
// The template is static; the address is assigned through the DOM.

let root = null;

// The daemon link, or null unless the node reported an http(s) address.
export function daemonLink(body) {
  if (body?.reason !== 'wallet_moved' || typeof body.address !== 'string') return null;
  try {
    const url = new URL(body.address);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

export function mount(el) {
  root = el;
  el.innerHTML = `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Wallet</h2><span class="pill">ergo-walletd</span></div>
      <div class="panel__body w-preauth">
        <p>This node hosts no wallet. Keys, balances and payments live in the wallet daemon,
          <code>ergo-walletd</code>, which serves its own wallet page. Mining needs no wallet:
          the node pays block rewards to <code>[mining] miner_reward_address</code>.</p>
        <p data-wallet-daemon>Looking up the wallet daemon’s address…</p>
        <p><b>Moving a wallet this node hosted in an earlier release</b></p>
        <ol>
          <li>Adopt the copy the node published:
            <code>ergo-walletd adopt --handoff &lt;node data dir&gt;/wallet-handoff --data-dir &lt;wallet dir&gt;</code></li>
          <li>Create the daemon’s config:
            <code>ergo-walletd init --config &lt;dir&gt;/walletd.toml --data-dir &lt;wallet dir&gt; --node-url &lt;this node’s API URL&gt; --tcp 127.0.0.1:3033</code></li>
          <li>Add the <code>[[api.security.keys]]</code> entry it prints to <code>ergo-node.toml</code>, then restart the node.</li>
          <li>Start <code>ergo-walletd --config &lt;dir&gt;/walletd.toml</code> and open its page. Authorize with the
            contents of <code>&lt;dir&gt;/wallet-api-key</code>, then unlock with the wallet password you used before.</li>
        </ol>
        <p>A new wallet needs only steps 2 to 4; create or restore it on the daemon’s page.
          <code>docs/wallet-setup.md</code> has the details.</p>
      </div>
    </section>`;
}

export async function onShow() {
  const target = root?.querySelector('[data-wallet-daemon]');
  if (!target) return;
  let link = null;
  try {
    const r = await fetch('/wallet/ui', { cache: 'no-store', signal: AbortSignal.timeout(12000) });
    if (r.status === 410) link = daemonLink(await r.json());
  } catch {
    /* shown as unknown below */
  }
  if (!link) {
    target.textContent = 'The node reports no wallet daemon address. Set [wallet] daemon_address in ergo-node.toml to the daemon’s listener.';
    return;
  }
  const a = document.createElement('a');
  a.href = link;
  a.rel = 'noopener noreferrer';
  a.className = 'btn btn--primary btn--sm';
  a.textContent = `Open the wallet daemon at ${link}`;
  target.replaceChildren(a, ' from ', Object.assign(document.createElement('code'), { textContent: '[wallet] daemon_address' }));
}
