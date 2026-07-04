// Miner attribution helpers shared by explorer / overview / mining views:
// pk → P2PK address resolution (server-side /utils/rawToAddress, session-
// cached), curated pool labels, own-node pk detection ("you" badge), and
// the standard miner DOM cell.
//
// POOL_LABELS is keyed by the P2PK address DERIVED FROM powSolutions.pk —
// the exact string the server emits as `miner_address` and that
// /utils/rawToAddress returns. It is NOT the pool's long P2S payout
// address ("88dhg…"): each pool's mining pk was extracted from its
// reward-script payout address in the public explorer address book
// (marker 0x08cd + 33 bytes) and re-encoded as P2PK. Seeded 2026-07-05,
// verified against the last 720 mainnet blocks (~93% labeled). Curated
// by hand — refresh when pools rotate keys.
import { getJson } from './api-client.js';
import { truncMiddle } from './format.js';

const POOL_LABELS = new Map([
  ['9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx', '2Miners'],
  ['9gLHUWsNSjEi957E23ChviPKGnD76DoMuNg5ykjrvrvTBZTo5qv', 'HeroMiners'],
  ['9giun3ba4ZnPvxYdXpk89XvwWkmWqJNQpGxgTRz932PajDPjE2z', 'HeroMiners'],
  ['9eZ8u92tKiXZrojwjsHcdkPgQEDhpRSfcUZ2LnGrBe7qtyeUNJ8', 'WoolyPooly'],
  ['9ff7YXNuQtZ5v9PSgkfft6J1vpnqTvsWZ9J81W6To5EdBxqmVNF', 'Nanopool'],
  ['9gsbKAia1ARpA2zyotMzrWnJvmfuqcPemue5pfbm87Mnt5h1Tmm', 'Kryptex'],
  ['9gqURqNpyUdNXBDH6t9p8cYrhQvzz8UEPsyoPyZNhTi8J2QB4Le', 'K1 Pool'],
  ['9h6oo1SLQKs38niWiXDwL9D9gbdQ3P9rmL7x9uGwbJqLrCvqe4S', '666 Pool'],
  ['9hFPAU1x1NRsuCjUZmCCyptvosTxYbe5uDvPV7t2BjwbzbS1dH3', 'DX Pool'],
  ['9fu1mLunnUUYEdJSXRUu1KZDJyJZV4gajd1uEFMEBsCWLEAJENo', 'DX Pool'],
  ['9fr915vPsMmf8UxLEvkLJfbq1Tf9BGGVvZYVm2h27MCCnp3xdZT', 'JJ Pool'],
  ['9grr1mjq8jqczDTD9PgDFmApQ9ifcV5zmBUdsgs6ynRBiC1x4im', 'Magic Pool'],
  ['9fTtqcMuSfURB658n68UhKwDVwW3FkepR3pJQ2eNde6uxM66G97', 'Solo Pool'],
  ['9eg5XhXFJNKSe1un72XB1G2ZQzYeqTAvcG8Q4MekV9J2xXh9SWj', 'Sigmanauts'],
  ['9ennYNGuHYz2C6JagPuFFMY17UHT6WMfzkKhDj3swDim7UE65VN', 'Sigmanauts'],
  ['9gbzYdhsZSv8SgsGRNu8apNgFeNRBjYgfqjBTiDKPbm4WchmZN2', 'Sigmanauts'],
]);

export function poolLabel(address) {
  return (address && POOL_LABELS.get(address)) || null;
}

// pk (hex) → P2PK address via GET /utils/rawToAddress. Only successes are
// cached, so a transient failure retries on the next view (the tokenMeta
// discipline from explorer.js).
const pkAddr = new Map();
export async function pkToAddress(pk) {
  if (!pk) return null;
  if (pkAddr.has(pk)) return pkAddr.get(pk);
  const got = await getJson(`/utils/rawToAddress/${pk}`);
  if (got?.address) {
    pkAddr.set(pk, got.address);
    return got.address;
  }
  return null;
}

// Own-node mining pk (what external miners mine to). /mining/* routes 404
// on non-mining nodes — probed once per session, null when absent.
let ownPk; // undefined = not probed yet; null = probed, none
let ownPkInflight = null;
export function ownPkHex() {
  return ownPk || null;
}
export function isOwnPk(pk) {
  return !!pk && !!ownPk && pk === ownPk;
}
export async function fetchOwnPk() {
  if (ownPk !== undefined) return ownPkHex();
  if (!ownPkInflight) {
    ownPkInflight = getJson('/mining/rewardPublicKey').then((r) => {
      ownPk = r?.rewardPubkey || null;
      return ownPk;
    });
  }
  await ownPkInflight;
  return ownPkHex();
}

// Standard miner cell: pool label (title = full address) or truncated
// address, linked into the explorer address view, plus the "you" pill
// when the pk is this node's own. `—` when the address is unknown.
export function minerNode(address, pk, opts = {}) {
  const w = document.createElement('span');
  w.className = 'mn-cell';
  if (!address) {
    w.textContent = '—';
    return w;
  }
  const a = document.createElement('a');
  a.className = 'ex-link';
  a.href = `#explorer/address/${address}`;
  const lbl = poolLabel(address);
  a.textContent = lbl || truncMiddle(address, opts.head ?? 8, opts.tail ?? 6);
  if (lbl) a.title = address;
  w.append(a);
  if (isOwnPk(pk)) {
    const you = document.createElement('span');
    you.className = 'pill pill--ok';
    you.textContent = 'you';
    w.append(document.createTextNode(' '), you);
  }
  return w;
}
