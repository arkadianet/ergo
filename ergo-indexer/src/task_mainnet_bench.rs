//! Manual archival replay. The source database is opened read-only; destinations
//! must live in this worktree's target directory. No node process is involved.

use super::*;
use std::path::{Path, PathBuf};

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_stored_block_transactions;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use redb::{ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};

const CHAIN: TableDefinition<u64, &[u8]> = TableDefinition::new("chain_index");
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const SECTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("block_sections");

struct Archive {
    db: ReadOnlyDatabase,
    end: u32,
    load_nanos: std::sync::atomic::AtomicU64,
}

fn source_error(source: impl std::error::Error + Send + Sync + 'static) -> IndexerError {
    IndexerError::ChainRead {
        operation: "read-only benchmark archive",
        source: Box::new(source),
    }
}

impl IndexerChainSource for Archive {
    fn committed_tip(&self) -> Result<ChainTip, IndexerError> {
        Ok(ChainTip {
            height: self.end,
            header_id: self.header_id_at(self.end)?.expect("archive endpoint"),
        })
    }

    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        let read = self.db.begin_read().map_err(source_error)?;
        let table = read.open_table(CHAIN).map_err(source_error)?;
        table
            .get(u64::from(height))
            .map_err(source_error)?
            .map(|row| {
                Ok(Digest32::from_bytes(row.value().try_into().map_err(
                    |_| source_error(std::io::Error::other("invalid archive header ID")),
                )?))
            })
            .transpose()
    }

    fn best_header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        self.header_id_at(height)
    }

    fn full_block(&self, id: &HeaderId) -> Result<Option<IndexerFullBlock>, IndexerError> {
        let started = Instant::now();
        let read = self.db.begin_read().map_err(source_error)?;
        let headers = read.open_table(HEADERS).map_err(source_error)?;
        let Some(bytes) = headers
            .get(id.as_bytes().as_slice())
            .map_err(source_error)?
        else {
            return Ok(None);
        };
        let mut reader = VlqReader::new(bytes.value());
        let header = read_header(&mut reader).map_err(source_error)?;
        assert!(reader.is_empty(), "header trailing bytes");
        let section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            id.as_bytes(),
            header.transactions_root.as_bytes(),
        );
        let sections = read.open_table(SECTIONS).map_err(source_error)?;
        let Some(bytes) = sections.get(section.as_slice()).map_err(source_error)? else {
            return Ok(None);
        };
        let transactions = read_stored_block_transactions(bytes.value()).map_err(source_error)?;
        assert_eq!(transactions.header_id.as_bytes(), id.as_bytes());
        self.load_nanos
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(Some(IndexerFullBlock {
            height: i32::try_from(header.height).expect("mainnet height"),
            header_id: *id,
            transactions: transactions.transactions,
        }))
    }
}

// Experimental decode overlap, confined to an immutable archive. At most two
// decoded blocks wait ahead of the writer; errors retain their position.
type Loaded = (HeaderId, Result<Option<IndexerFullBlock>, IndexerError>);
type DecodeQueue = (std::sync::mpsc::Receiver<Loaded>, Option<Loaded>);
enum ReplaySource {
    Direct(Arc<Archive>),
    Prefetch {
        archive: Arc<Archive>,
        receiver: std::sync::Mutex<Option<DecodeQueue>>,
        worker: Option<std::thread::JoinHandle<()>>,
    },
}
impl ReplaySource {
    fn prefetch(archive: Arc<Archive>, first: u32) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let source = archive.clone();
        let worker = std::thread::Builder::new()
            .name("benchmark-decode".into())
            .stack_size(ergo_ser::decode_stack::DECODE_THREAD_STACK_BYTES)
            .spawn(move || {
                for height in first..=source.end {
                    let id = source.header_id_at(height).unwrap().unwrap();
                    let loaded = source.full_block(&id);
                    if sender.send((id, loaded)).is_err() {
                        break;
                    }
                }
            })
            .unwrap();
        Self::Prefetch {
            archive,
            receiver: std::sync::Mutex::new(Some((receiver, None))),
            worker: Some(worker),
        }
    }
    fn archive(&self) -> &Archive {
        match self {
            Self::Direct(archive) | Self::Prefetch { archive, .. } => archive,
        }
    }
}
impl IndexerChainSource for ReplaySource {
    fn committed_tip(&self) -> Result<ChainTip, IndexerError> {
        self.archive().committed_tip()
    }
    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        self.archive().header_id_at(height)
    }
    fn best_header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        self.archive().best_header_id_at(height)
    }
    fn full_block(&self, id: &HeaderId) -> Result<Option<IndexerFullBlock>, IndexerError> {
        match self {
            Self::Direct(archive) => archive.full_block(id),
            Self::Prefetch { receiver, .. } => {
                let mut guard = receiver.lock().unwrap();
                let (channel, pending) = guard.as_mut().unwrap();
                let (loaded_id, block) = pending.take().unwrap_or_else(|| channel.recv().unwrap());
                if *id == loaded_id {
                    block
                } else {
                    // The task can discard a loaded block when its time budget
                    // expires. Re-read that block without consuming its successor.
                    *pending = Some((loaded_id, block));
                    self.archive().full_block(id)
                }
            }
        }
    }
}
impl Drop for ReplaySource {
    fn drop(&mut self) {
        if let Self::Prefetch {
            receiver, worker, ..
        } = self
        {
            // Close before joining so a producer blocked on a full queue exits.
            receiver.get_mut().unwrap().take();
            worker.take().unwrap().join().unwrap();
        }
    }
}

fn destination(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var(variable).expect(variable));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target")
        .canonicalize()
        .unwrap();
    assert!(path.is_absolute());
    assert!(path
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .starts_with(root));
    assert!(!path.is_symlink());
    path
}

fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn write_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/io")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("write_bytes: "))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "requires a verified read-only mainnet archive and explicit target paths"]
fn benchmark_archival_catchup() {
    let source = PathBuf::from(std::env::var("INDEXER_BENCH_STATE").unwrap());
    assert!(source.parent().unwrap().join("READY").exists());
    let end = std::env::var("INDEXER_BENCH_END").unwrap().parse().unwrap();
    let mode = std::env::var("INDEXER_BENCH_MODE").unwrap();
    let path = destination("INDEXER_BENCH_INDEX");
    let archive = Arc::new(Archive {
        db: ReadOnlyDatabase::open(source).unwrap(),
        end,
        load_nanos: std::sync::atomic::AtomicU64::new(0),
    });
    let (store, _) = IndexerStore::open(&path).unwrap();
    let start_height = store.read_meta().unwrap().indexed_height;
    let handle = IndexerHandle::with_store(store, start_height);
    let chain = if mode == "prefetch" {
        ReplaySource::prefetch(archive.clone(), start_height as u32 + 1)
    } else {
        ReplaySource::Direct(archive.clone())
    };
    let mut task = IndexerTask::new(handle.clone(), Arc::new(chain));
    let ticks_per_second: f64 = String::from_utf8(
        std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap();
    let writes = write_bytes();
    let cpu = cpu_ticks();
    let start = Instant::now();
    let mut commits = 0_u64;
    while handle.indexed_height() < u64::from(end) {
        let poll = match mode.as_str() {
            "single" => task.step(),
            "legacy" => task.step_with_budget(16, Duration::from_millis(50), 8 * 1024 * 1024),
            "adaptive" | "prefetch" => task.step_batch(),
            _ => panic!("unknown mode: {mode}"),
        };
        assert!(matches!(poll, IndexerPoll::Applied(_)), "{poll:?}");
        commits += 1;
        if commits.is_multiple_of(1000) {
            eprintln!(
                "height={} elapsed={:.1}s",
                handle.indexed_height(),
                start.elapsed().as_secs_f64()
            );
        }
    }
    let seconds = start.elapsed().as_secs_f64();
    let cpu_seconds = (cpu_ticks() - cpu) as f64 / ticks_per_second;
    let writes = write_bytes() - writes;
    println!("BENCH {{\"mode\":\"{mode}\",\"start\":{start_height},\"end\":{end},\"seconds\":{seconds},\"blocks_per_second\":{},\"commits\":{commits},\"file_bytes\":{},\"write_bytes\":{writes},\"cpu_seconds\":{cpu_seconds}}}",
        (u64::from(end) - start_height) as f64 / seconds, std::fs::metadata(&path).unwrap().len());
    println!(
        "LOAD_SECONDS {}",
        archive.load_nanos.load(Ordering::Relaxed) as f64 / 1e9
    );
    println!("APPLY_SECONDS {}", task.profile.apply.as_secs_f64());
    println!("COMMIT_SECONDS {}", task.profile.commit.as_secs_f64());
    // All commits are Immediate; close is outside the timed interval.
}

#[test]
#[ignore = "manual streaming comparison of every row in two benchmark indexes"]
fn archival_indexes_are_identical() {
    let a = ReadOnlyDatabase::open(destination("INDEXER_BENCH_INDEX")).unwrap();
    let b = ReadOnlyDatabase::open(destination("INDEXER_BENCH_REFERENCE")).unwrap();
    assert_all_rows_equal(&a.begin_read().unwrap(), &b.begin_read().unwrap());
}

pub(super) fn assert_all_rows_equal(a: &redb::ReadTransaction, b: &redb::ReadTransaction) {
    use redb::{ReadableTableMetadata, TableHandle};
    let names = |read: &redb::ReadTransaction| {
        read.list_tables()
            .unwrap()
            .map(|table| table.name().to_owned())
            .collect::<Vec<_>>()
    };
    let tables = names(a);
    assert_eq!(tables, names(b));
    for name in tables {
        macro_rules! compare {
            ($key:ty) => {{
                let definition = TableDefinition::<$key, &[u8]>::new(&name);
                let left = a.open_table(definition).unwrap();
                let right = b.open_table(definition).unwrap();
                assert_eq!(left.len().unwrap(), right.len().unwrap(), "{name} count");
                for (left, right) in left.iter().unwrap().zip(right.iter().unwrap()) {
                    let (lk, lv) = left.unwrap();
                    let (rk, rv) = right.unwrap();
                    assert_eq!(lk.value(), rk.value(), "{name} key");
                    assert_eq!(lv.value(), rv.value(), "{name} value");
                }
            }};
        }
        match name.as_str() {
            "indexer_meta" => compare!(&str),
            "indexer_undo" => compare!(u64),
            "unspent_by_creation_height" => compare!((u32, i64)),
            "indexed_box" | "indexed_tx" | "indexed_address" | "indexed_template"
            | "indexed_token" | "numeric_box" | "numeric_tx" | "segments" => compare!(&[u8]),
            _ => panic!("unhandled index table: {name}"),
        }
    }
}
