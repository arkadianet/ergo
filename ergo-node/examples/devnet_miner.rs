//! Single-threaded CPU miner for a **difficulty-1 devnet**, driving a running
//! node's external-miner REST path (`GET /mining/candidate` →
//! `POST /mining/solution`).
//!
//! This is the out-of-process twin of `ergo-node/tests/mining_e2e.rs`'s
//! in-process solve loop: same `calc_n` / `hit_for_v2` inputs, the same strict
//! `hit < target` acceptance rule the node's own `verify_pow_solution` re-runs
//! on the submit path, and the same minimal `{"n": <nonce hex>}` solution body
//! (the node injects the candidate's miner pubkey at accept time, per Scala's
//! `CandidateGenerator`).
//!
//! It exists to bootstrap a fresh devnet past genesis — e.g. to obtain the
//! height-1 header id — without standing up a GPU miner. It is viable ONLY at
//! trivial difficulty: a single CPU thread scanning nonces sequentially finds a
//! hit essentially on the first try when the target is the secp256k1 order, and
//! essentially never otherwise. It is not a production miner.
//!
//! The `version` fed to `calc_n` is read from `/info`
//! (`parameters.blockVersion`), the same active-params value the candidate's
//! header carries — the header version must agree between the miner's hit
//! computation and the node's re-verify.
//!
//! Usage:
//!   cargo run --example devnet_miner -- \
//!     --api http://127.0.0.1:19199 --api-key hello --blocks 5
//!
//! Writes only via `POST /mining/solution`; every other call is a read.

use std::time::Duration;

use clap::Parser;
use num_bigint::BigUint;
use reqwest::Client;

use ergo_crypto::autolykos::common::calc_n;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_rest_json::mining::WorkMessageJson;

/// Boxed-error result: this example has no typed-error surface to preserve and
/// the workspace carries no `anyhow`.
type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Bound for waiting on a candidate at a given height, and on the tip advancing
/// after an accepted solution. Generous: the candidate engine republishes off
/// the action loop's ~1s tick.
const POLL_ATTEMPTS: u32 = 120;
const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Parser, Debug)]
#[command(
    name = "devnet_miner",
    about = "CPU-mine a difficulty-1 Ergo devnet over the external-miner REST path"
)]
struct Args {
    /// Base URL of the node's REST API.
    #[arg(long, default_value = "http://127.0.0.1:19199")]
    api: String,

    /// Value for the `api_key` header.
    #[arg(long, default_value = "hello")]
    api_key: String,

    /// Number of blocks to mine before exiting.
    #[arg(long, default_value_t = 5)]
    blocks: u32,
}

impl Args {
    /// `self.api` with any trailing slash removed, so `{base}/info` never
    /// produces a double slash.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api.trim_end_matches('/'))
    }
}

/// The `/info` fields this miner needs: the current full-block tip and the
/// active block version (the header version the candidate carries, which feeds
/// `calc_n`).
struct NodeInfo {
    full_height: u32,
    block_version: u8,
}

async fn get_info(client: &Client, args: &Args) -> Res<NodeInfo> {
    let resp = client
        .get(args.url("/info"))
        .header("api_key", &args.api_key)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(format!("GET /info returned {status}: {body}").into());
    }
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let full_height = v["fullHeight"]
        .as_u64()
        .ok_or_else(|| format!("/info has no numeric fullHeight: {body}"))?
        as u32;
    let block_version = v["parameters"]["blockVersion"]
        .as_u64()
        .ok_or_else(|| format!("/info has no numeric parameters.blockVersion: {body}"))?
        as u8;
    Ok(NodeInfo {
        full_height,
        block_version,
    })
}

/// Poll `GET /mining/candidate` until it serves a template for `height`.
///
/// After a block applies, the engine rebuilds for the new tip but the published
/// template lags the tip advance by a tick or two, so the served candidate may
/// briefly still be the previous height's. Re-polling — rather than solving a
/// stale template and submitting a duplicate — is the handling for that.
async fn poll_candidate_at_height(
    client: &Client,
    args: &Args,
    height: u32,
) -> Res<WorkMessageJson> {
    let mut last = String::from("nothing");
    for _ in 0..POLL_ATTEMPTS {
        let resp = client
            .get(args.url("/mining/candidate"))
            .header("api_key", &args.api_key)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if status.is_success() {
            let work: WorkMessageJson = serde_json::from_str(&body)
                .map_err(|e| format!("parse candidate {body:?}: {e}"))?;
            if work.h == Some(height) {
                return Ok(work);
            }
            last = format!("candidate at height {:?}", work.h);
        } else {
            last = format!("{status}: {body}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(format!(
        "no candidate for height {height} within {:?}; last seen: {last}",
        POLL_INTERVAL * POLL_ATTEMPTS,
    )
    .into())
}

/// Find the first 8-byte nonce whose Autolykos v2 hit is strictly below the
/// target. Strict `<` mirrors `check_pow_v2`, which the node re-runs
/// authoritatively on submit — a nonce accepted on `<=` would be rejected there.
fn solve(msg: &[u8; 32], height: u32, version: u8, target: &BigUint) -> [u8; 8] {
    let n = calc_n(version, height);
    for nonce_u64 in 0u64.. {
        let nonce = nonce_u64.to_be_bytes();
        if &hit_for_v2(msg, &nonce, height, n) < target {
            return nonce;
        }
    }
    unreachable!("a difficulty-1 target is always satisfiable by some 8-byte nonce");
}

/// Decode a candidate's 64-char hex `msg` into the 32 bytes the solver hashes.
fn msg_bytes(work: &WorkMessageJson) -> Res<[u8; 32]> {
    let raw = hex::decode(&work.msg)?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| format!("candidate msg is not 32 bytes: {}", work.msg).into())
}

/// Submit a nonce. Only `n` is sent: `pk` / `w` / `d` are optional in the Scala
/// decoder and the node injects the candidate's miner pubkey at accept time.
async fn submit_solution(client: &Client, args: &Args, nonce: [u8; 8]) -> Res<()> {
    let resp = client
        .post(args.url("/mining/solution"))
        .header("api_key", &args.api_key)
        .json(&serde_json::json!({ "n": hex::encode(nonce) }))
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(format!("POST /mining/solution rejected ({status}): {text}").into());
    }
    Ok(())
}

/// Poll `/info` until `fullHeight` reaches `height`.
async fn poll_full_height(client: &Client, args: &Args, height: u32) -> Res<bool> {
    for _ in 0..POLL_ATTEMPTS {
        if get_info(client, args).await?.full_height >= height {
            return Ok(true);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Ok(false)
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::parse();
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

    let info = get_info(&client, &args).await?;
    println!(
        "node {} at height {} (block version {})",
        args.api, info.full_height, info.block_version,
    );

    let mut height = info.full_height;
    for i in 1..=args.blocks {
        let next = height + 1;
        let work = poll_candidate_at_height(&client, &args, next).await?;
        let started = std::time::Instant::now();
        let nonce = solve(&msg_bytes(&work)?, next, info.block_version, &work.b);
        submit_solution(&client, &args, nonce).await?;
        if !poll_full_height(&client, &args, next).await? {
            return Err(format!(
                "solution for height {next} accepted but the tip never advanced (stuck at {})",
                get_info(&client, &args).await?.full_height,
            )
            .into());
        }
        println!(
            "block {i}/{} ACCEPTED at height {next} (nonce {}, solved in {:?})",
            args.blocks,
            hex::encode(nonce),
            started.elapsed(),
        );
        height = next;
    }

    println!("done — devnet tip is now height {height}");
    Ok(())
}
