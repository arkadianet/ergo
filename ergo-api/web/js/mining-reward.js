import { erg, num } from './format.js';

// The emission API reports the miner share after the EIP-27 allocation.
// Keep the two destinations explicit instead of presenting a combined payout.
export function miningReward(emission, context) {
  const root = document.createElement('div');
  root.className = 'mining-reward';
  const title = document.createElement('div');
  title.className = 'mining-reward__title';
  title.textContent = `Reward at ${context} height${emission.height == null ? '' : ` · ${num(emission.height)}`}`;
  const amounts = document.createElement('dl');
  amounts.className = 'mining-reward__amounts';
  const amount = (label, value) => {
    const group = document.createElement('div');
    const term = document.createElement('dt');
    term.textContent = label;
    const detail = document.createElement('dd');
    detail.textContent = `${erg(value).replace(/\.0$/, '')} ERG`;
    group.append(term, detail);
    amounts.append(group);
  };
  amount('Miner reward', emission.minerReward);
  const hasReserve = Number(emission.reemitted) > 0;
  if (hasReserve) amount('Re-emission reserve', emission.reemitted);
  const note = document.createElement('p');
  note.className = 'mining-reward__note';
  note.textContent = `${hasReserve ? 'Re-emission sets aside ERG for future mining rewards (EIP-27). ' : ''}Miner reward excludes transaction fees.`;
  root.append(title, amounts, note);
  return root;
}
