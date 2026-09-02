//! Ignored micro-benchmark for ADProofs regeneration cost (issue #257,
//! workstream A step 1).
//!
//! Measures the three phases the UTXO apply path used to pay per block
//! when [`crate::StateStore::regenerate_ad_proofs`] was the proofHash
//! check (PR #256), split so the O(tree size) part is visible on its own:
//!
//! 1. **hydrate** — [`crate::avl::hydrate::hydrate_batch_avl_prover`]
//!    materializes the whole arena-backed AVL+ tree into the upstream
//!    `Rc<RefCell<Node>>` prover graph. O(tree size) arena reads + heap.
//! 2. **prove** — [`super::dry_run::apply_change_set_to_prover`] runs the
//!    canonical op stream (lookups → removes → inserts) and emits the
//!    proof bytes. O(block size · log tree).
//! 3. **verify** — [`super::dry_run::self_check_candidate_proof`] replays
//!    the proof through the production `AvlVerifier`. This is the same
//!    work `verify_shipped_ad_proofs` does (PR #265) and is the O(block)
//!    alternative to regenerating at all.
//!
//! A fourth column times the raw state-apply core (tree remove/insert for
//! the same change-set) so the regeneration cost has a denominator that
//! is measured rather than asserted.
//!
//! Run it explicitly — it is `#[ignore]`d because it builds multi-hundred-MB
//! fixtures and takes minutes:
//!
//! ```text
//! cargo test -p ergo-state --release adproofs_regen_cost_table -- --ignored --nocapture
//! ```
//!
//! Knobs (env): `ERGO_REGEN_BENCH_SIZES` (comma-separated UTXO-set sizes,
//! default `10000,100000,1000000`), `ERGO_REGEN_BENCH_RUNS` (default 5).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_primitives::digest::Digest32;
use redb::Database;

use super::dry_run::{
    apply_change_set_to_prover, self_check_candidate_proof, DryRunInsertMap, DryRunRemoveMap,
};
use super::{node_to_bytes, AVL_NODES};
use crate::avl::arena::CachedDiskArena;
use crate::avl::hydrate::hydrate_batch_avl_prover;
use crate::avl::tree::AvlTree;

/// Serialized-box stand-in length. Mainnet boxes are mostly 80-120 bytes;
/// the value only affects node byte-size (and therefore LRU occupancy),
/// not the shape of the walk.
const VALUE_LEN: usize = 90;

/// Arena clean-cache budget used for the headline numbers — the shipped
/// default (`StateStore::DEFAULT_CACHE_BYTES`).
const DEFAULT_BUDGET: usize = 1024 * 1024 * 1024;

/// Constrained budget used for the cache-pressure row: small enough that a
/// large tree cannot be held resident, which is the #264 regime.
const TIGHT_BUDGET: usize = 16 * 1024 * 1024;

// ----- helpers -----

/// Deterministic 32-byte key for index `i` (splitmix64, four draws).
fn key(i: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5DEE_CE66_D3A2_1B37;
    for chunk in out.chunks_exact_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    out
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// A persisted synthetic UTXO set: `n` boxes written into a real redb
/// `AVL_NODES` table, so every measured hydration reads through the same
/// `CachedDiskArena` path production uses.
struct Fixture {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    root_id: u64,
    tree_height: u8,
    next_id: u64,
    root_label: Digest32,
    n: usize,
}

impl Fixture {
    fn build(n: usize) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::create(dir.path().join("bench.redb")).expect("create redb"));
        // Construction runs at the shipped default budget; every node it
        // writes is dirty (non-evictable) until the commit below, so the
        // budget only bounds the clean LRU. The measured runs get their
        // own cold, budgeted arena.
        let arena = CachedDiskArena::new(Arc::clone(&db), DEFAULT_BUDGET);
        let mut tree = AvlTree::new_disk_backed(Box::new(arena));
        for i in 0..n as u64 {
            tree.insert(key(i), vec![0xAB; VALUE_LEN]);
        }

        let write_txn = crate::begin_write_qr(&db).expect("begin write");
        {
            let mut table = write_txn.open_table(AVL_NODES).expect("open avl_nodes");
            for (node_id, node) in tree.all_nodes() {
                table
                    .insert(node_id, node_to_bytes(&node).as_slice())
                    .expect("persist node");
            }
        }
        write_txn.commit().expect("commit nodes");

        Fixture {
            root_id: tree.root_id(),
            tree_height: tree.tree_height(),
            next_id: tree.next_id(),
            root_label: tree.root_label(),
            n,
            _dir: dir,
            db,
        }
    }

    /// A tree whose arena cache is empty — every node the hydration walk
    /// touches is a cold redb read.
    fn cold_tree(&self, budget: usize) -> AvlTree {
        let arena = CachedDiskArena::new(Arc::clone(&self.db), budget);
        AvlTree::new_with_arena(
            Box::new(arena),
            self.root_id,
            self.tree_height,
            self.next_id,
            self.root_label,
        )
    }

    /// Synthetic block change-set: `txs` transactions, each with one data
    /// input (lookup), two spent boxes (removes) and two created boxes
    /// (inserts). `txs == 0` models an empty block.
    fn change_set(&self, txs: usize) -> ChangeSet {
        let mut lookups = Vec::with_capacity(txs);
        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        if txs == 0 {
            return ChangeSet {
                lookups,
                to_remove,
                to_insert,
            };
        }
        // Spread the touched indices across the whole key space so the
        // proof visits independent root-to-leaf paths, as a real block does.
        let stride = (self.n / (3 * txs).max(1)).max(1) as u64;
        for i in 0..txs as u64 {
            lookups.push(key((i * stride) % self.n as u64));
            to_remove.insert(key(((i * 2 + 1) * stride) % self.n as u64), ());
            to_remove.insert(key(((i * 2 + 2) * stride) % self.n as u64), ());
            to_insert.insert(key(self.n as u64 + i * 2), vec![0xCD; VALUE_LEN]);
            to_insert.insert(key(self.n as u64 + i * 2 + 1), vec![0xCD; VALUE_LEN]);
        }
        ChangeSet {
            lookups,
            to_remove,
            to_insert,
        }
    }
}

struct ChangeSet {
    lookups: Vec<[u8; 32]>,
    to_remove: DryRunRemoveMap,
    to_insert: DryRunInsertMap,
}

#[derive(Default)]
struct Row {
    arena_setup: Vec<Duration>,
    hydrate: Vec<Duration>,
    prove: Vec<Duration>,
    verify: Vec<Duration>,
    apply: Vec<Duration>,
    proof_len: usize,
    nodes_read: u64,
}

fn measure(fx: &Fixture, cs: &ChangeSet, budget: usize, runs: usize) -> Row {
    let mut row = Row::default();
    // One untimed warm-up so the OS page cache state is the same for
    // every timed run (the arena LRU is still cold per run by construction).
    for run in 0..=runs {
        // Arena construction is timed separately: `CachedDiskArena::new`
        // sizes its clean LRU as `byte_budget / 100` entries, so at the
        // shipped 1 GiB default it allocates a ~10.7M-slot table. That is a
        // once-per-open cost in production, not a per-block one, and must
        // not be smeared into the hydration number.
        let t_arena = Instant::now();
        let tree = fx.cold_tree(budget);
        let arena_setup = t_arena.elapsed();
        tree.arena_reset_read_count();
        let parent_root = tree.root_digest();

        let t0 = Instant::now();
        let mut prover = hydrate_batch_avl_prover(&tree).expect("hydrate");
        let hydrate = t0.elapsed();
        let nodes_read = tree.arena_read_count();

        let t1 = Instant::now();
        let (new_root, proof) =
            apply_change_set_to_prover(&mut prover, &cs.lookups, &cs.to_remove, &cs.to_insert)
                .expect("prove");
        let prove = t1.elapsed();
        drop(prover);

        let t2 = Instant::now();
        self_check_candidate_proof(
            &parent_root,
            &cs.lookups,
            &cs.to_remove,
            &cs.to_insert,
            &proof,
            &new_root,
        )
        .expect("verify replay");
        let verify = t2.elapsed();

        // Denominator: the state-apply core for the same change-set, on
        // its own cold arena so the hydration walk hasn't warmed it.
        let mut apply_tree = fx.cold_tree(budget);
        let t3 = Instant::now();
        for box_id in cs.to_remove.keys() {
            apply_tree.remove(box_id);
        }
        for (box_id, value) in &cs.to_insert {
            apply_tree.insert(*box_id, value.clone());
        }
        let apply = t3.elapsed();
        assert_eq!(
            apply_tree.root_digest().as_bytes(),
            new_root.as_bytes(),
            "state-apply core must reach the prover's root"
        );

        if run == 0 {
            continue; // warm-up
        }
        row.arena_setup.push(arena_setup);
        row.hydrate.push(hydrate);
        row.prove.push(prove);
        row.verify.push(verify);
        row.apply.push(apply);
        row.proof_len = proof.len();
        row.nodes_read = nodes_read;
    }
    row
}

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(name) {
        Ok(v) => v
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect(),
        Err(_) => default.to_vec(),
    }
}

// ----- benchmark -----

#[test]
#[ignore = "micro-benchmark: minutes of runtime and hundreds of MB of fixtures"]
fn adproofs_regen_cost_table() {
    let sizes = env_usize_list("ERGO_REGEN_BENCH_SIZES", &[10_000, 100_000, 1_000_000]);
    let runs: usize = std::env::var("ERGO_REGEN_BENCH_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let tx_counts = [0usize, 10, 100, 500];

    println!(
        "\n| UTXO boxes | cache | block txs | ops | arena setup ms | nodes read | hydrate ms | \
         prove ms | regen total ms | verify-shipped ms | state-apply ms | proof B |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");

    for n in sizes {
        let fx = Fixture::build(n);
        for budget in [DEFAULT_BUDGET, TIGHT_BUDGET] {
            let budget_label = format!("{} MiB", budget / (1024 * 1024));
            for txs in tx_counts {
                let cs = fx.change_set(txs);
                let ops = cs.lookups.len() + cs.to_remove.len() + cs.to_insert.len();
                let row = measure(&fx, &cs, budget, runs);
                let hyd = median(row.hydrate.clone());
                let prv = median(row.prove.clone());
                println!(
                    "| {n} | {budget_label} | {txs} | {ops} | {:.2} | {} | {:.2} | {:.2} | \
                     {:.2} | {:.2} | {:.2} | {} |",
                    ms(median(row.arena_setup)),
                    row.nodes_read,
                    ms(hyd),
                    ms(prv),
                    ms(hyd) + ms(prv),
                    ms(median(row.verify)),
                    ms(median(row.apply)),
                    row.proof_len,
                );
            }
        }
    }
    println!();
}
