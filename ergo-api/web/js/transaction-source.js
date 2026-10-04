import { lookupJson } from './api-client.js';

// The slim detail route hides its source. Only confirmed-only indexed data or
// a mempool-only response proves status; index readiness cannot supply proof.
export async function loadTransaction(id, read = lookupJson) {
  const results = await Promise.allSettled([
    read(`/blockchain/transaction/byId/${id}`),
    read(`/transactions/unconfirmed/byTransactionId/${id}`),
    read(`/api/v1/transactions/${id}/detail`),
  ]);
  const [rich, pool, slim] = results.map((r) => r.status === 'fulfilled' ? r.value : null);
  const failures = results.filter((r) => r.status === 'rejected').map((r) => r.reason);
  const status = rich ? 'confirmed' : pool ? 'unconfirmed' : slim ? 'unknown' : failures.length ? 'unavailable' : 'absent';
  return { rich, pool, slim, status, failures };
}
