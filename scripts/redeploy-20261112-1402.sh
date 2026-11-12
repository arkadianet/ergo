#!/usr/bin/env bash
# ============================================================================
# 2026-11-12 14:02 (AEST) window-close redeploy — checklist + executor
#
# Plan: docs/phase0-observer.md "Redeploy plan" (step 2: mainnet node at
# 14:02; step 3: observer + crawlers after; rollback triggers in the
# "Mainnet rollback triggers" table; reason-code set: ConnectError,
# ergo-p2p/src/peer_manager/limits.rs).
#
# Subcommands (run in order):
#   backup        hash + snapshot everything that will change (pre-swap)
#   swap-node     step 2: stop ergo-rust-archival, atomic-swap the combined
#                 ergo-node, start with the first-10-min debug window,
#                 record T0
#   monitor       evaluate rollback triggers 1-6 for the first 15 minutes;
#                 removes the debug drop-in at T0+10 min; rolls back on a
#                 trigger and stops step 3 if the trigger was #3
#   swap-observe  step 3: restart observer + both crawlers on the new build
#                 (only after monitor passed, and NOT after a #3 rollback)
#   rollback      manual rollback of step 2 to the pre-phase-0 state
#   status        quick read-only state summary
#
# All actions append to $LOG (the redeploy log — the dataset boundary note
# cites it). Backups with sha256 land in $BKS; the staged-binary hashes are
# pinned from BUILD-INFO.txt and re-verified at every swap.
# ============================================================================
set -euo pipefail

OBS=/home/arkadias/observation
STAGE=$OBS/staging
RDIR=$OBS/redeploy-20261112
BKS=$RDIR/backups
LOG=$RDIR/redeploy.log
STATE=$RDIR/state.env

NODE_DIR=/home/arkadias/nodes/rust-mainnet
NODE_BIN=$NODE_DIR/ergo-node
NODE_TOML=$NODE_DIR/ergo-node.toml
OBS_DIR=$OBS/mainnet-standalone
CRW_DIR=$OBS/mainnet-crawler
CRWT_DIR=$OBS/testnet-crawler

UNIT=ergo-rust-archival
OBS_UNIT=ergo-phase0-observer
CRW_UNIT=ergo-phase0-crawler
CRWT_UNIT=ergo-phase0-crawler-testnet

DROPIN_DIR=$HOME/.config/systemd/user/ergo-rust-archival.service.d
DROPIN=$DROPIN_DIR/30-phase0-debug-window.conf
# Mirrors ergo-node.toml [logging] (default_level=info, rdb=warn) plus the
# handshake parse-failure target at debug for the first 10 minutes
# (trigger 3(b); the parse-failure line is `handshake failed ... error=
# "parse handshake: ..."` at DEBUG, ergo-node/src/peer_loop.rs:317).
RUST_LOG_WINDOW="info,redb=warn,ergo_node::peer_loop=debug"

# Pinned staged hashes (BUILD-INFO.txt, 2026-11-12 14:02 redeploy).
EXP_NODE=d1e76de3c0f211b776ec75cee33553d71110fb212efbfd631a4bb37353fe1ebb
EXP_OBSERVER=4033e6a13e21cea4b660b07249da9bafd7d857e4bf1a8277e273a0157d6d9de7
EXP_CRAWLER=1234ba9f92cce76558aa14a9907467a1e4269590c2e54eac7e3699291d5df8c2

# Reason-code set (ConnectError, ergo-p2p/src/peer_manager/limits.rs):
#   already connected | peer is banned | max connections reached |
#   no inbound slots available | per-IP limit reached |
#   per-subnet limit reached | self-connection detected via session_id |
#   peer version ... below minimum | unknown peer
TRIGGER3A='self-connection detected via session_id'
PARSE_BURST_THRESHOLD=5   # parse failures in any 60 s window => trigger 3(b)

mkdir -p "$RDIR" "$BKS"
log() { printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >>"$LOG"; echo "$*"; }
die() { log "ERROR: $*"; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
epoch() { date -d "$1" +%s 2>/dev/null || echo 0; }
now_s() { date +%s; }

journal_since() { # $1 = "since" arg
  journalctl --user -u "$UNIT" --no-pager --since "$1" 2>/dev/null || true
}
latest_field() { # $1 = field name (peers|bans|best_full_block_height|gap|storage_health)
  journal_since "@$T0" | grep -oE "(^| )$1=\"?[0-9]+\"?( |\$)" 2>/dev/null \
    | grep -oE '[0-9]+' | tail -1 || true
}
latest_storage_health() {
  journal_since "@$T0" | grep -oE 'storage_health="[^"]*"' | tail -1 \
    | grep -oE '"[^"]*"' | tr -d '"' || true
}

verify_staged() {
  local h
  for pair in "$STAGE/ergo-node:$EXP_NODE" \
              "$STAGE/observer:$EXP_OBSERVER" \
              "$STAGE/crawler:$EXP_CRAWLER"; do
    local f=${pair%%:*} exp=${pair##*:}
    [ -f "$f" ] || die "staged binary missing: $f"
    h=$(sha "$f")
    [ "$h" = "$exp" ] || die "staged $f hash $h != expected $exp (BUILD-INFO.txt)"
    log "verified staged $(basename "$f") sha256=$h"
  done
}

# ---------------------------------------------------------------- backup ----
cmd_backup() {
  local ts
  ts=$(date +%Y%m%dT%H%M%SZ)
  log "=== BACKUP start ($ts) ==="
  log "pre-swap service states:"
  for u in "$UNIT" "$OBS_UNIT" "$CRW_UNIT" "$CRWT_UNIT" ergo-rust-testnet; do
    log "  $u: $(systemctl --user is-active "$u" 2>/dev/null || echo unknown)"
  done
  T0=0
  log "pre-swap gauges (latest before swap): peers=$(latest_field peers || echo '?') bans=$(latest_field bans || echo '?') tip=$(latest_field best_full_block_height || echo '?')"
  log "pre-swap /api/v1/info: $(curl -s --max-time 5 127.0.0.1:9063/api/v1/info | head -c 300)"
  for pair in "$NODE_BIN:ergo-node" "$NODE_TOML:ergo-node.toml" \
              "$OBS_DIR/observer:observer" \
              "$CRW_DIR/crawler:crawler-mainnet" \
              "$CRWT_DIR/crawler:crawler-testnet"; do
    local f=${pair%%:*} name=${pair##*:}
    cp -p "$f" "$BKS/$name.$ts"
    log "backup $name -> $BKS/$name.$ts sha256=$(sha "$BKS/$name.$ts")"
  done
  {
    for f in "$BKS"/*."$ts" "$STAGE"/ergo-node "$STAGE"/observer "$STAGE"/crawler; do
      sha256sum "$f"
    done
  } > "$BKS/manifest.$ts.sha256"
  log "manifest written: $BKS/manifest.$ts.sha256"
  verify_staged
  log "=== BACKUP done ==="
}

# ------------------------------------------------------------- swap-node ----
cmd_swap_node() {
  verify_staged
  log "=== SWAP-NODE (step 2) start ==="
  log "stopping $UNIT (TimeoutStopSec=600; may take a while on a clean shutdown)"
  timeout 660 systemctl --user stop "$UNIT" || die "stop failed or timed out"
  log "stopped; pre-swap binary sha256=$(sha "$NODE_BIN")"

  # Atomic swap: stage next to the target (same filesystem), rename over it.
  install -m 755 "$STAGE/ergo-node" "$NODE_DIR/.ergo-node.new"
  mv -f "$NODE_DIR/.ergo-node.new" "$NODE_BIN"
  log "swapped ergo-node; post-swap sha256=$(sha "$NODE_BIN") (expected $EXP_NODE)"
  [ "$(sha "$NODE_BIN")" = "$EXP_NODE" ] || die "post-swap hash mismatch"

  # Debug window for trigger 3(b): peer_loop parse failures at DEBUG for
  # the first 10 minutes (monitor removes the drop-in at T0+10 min).
  mkdir -p "$DROPIN_DIR"
  printf '[Service]\nEnvironment="RUST_LOG=%s"\n' "$RUST_LOG_WINDOW" >"$DROPIN"
  systemctl --user daemon-reload
  log "debug window drop-in installed: RUST_LOG=$RUST_LOG_WINDOW"

  systemctl --user start "$UNIT"
  sleep 3
  local active t0
  active=$(systemctl --user is-active "$UNIT" || true)
  [ "$active" = "active" ] || die "service not active after start (state: $active)"
  t0=$(systemctl --user show -p ActiveEnterTimestamp --value "$UNIT")
  [ "$(epoch "$t0")" -gt 0 ] || die "cannot read T0 (ActiveEnterTimestamp: $t0)"
  T0=$(epoch "$t0")
  printf 'T0=%s\nT0_ISO=%s\n' "$T0" "$t0" >"$STATE"
  log "T0 = $t0 (epoch $T0) — dataset boundary: mono_ns session break in the node hook stream"
  log "=== SWAP-NODE done; run 'monitor' now ==="
}

# --------------------------------------------------------------- monitor ----
cmd_monitor() {
  [ -f "$STATE" ] || die "no T0 recorded (run swap-node first); or: monitor <epoch>"
  if [ "${1:-}" ]; then T0=$1; else . "$STATE"; fi
  log "=== MONITOR start (T0=$(date -d "@$T0" '+%Y-%m-%dT%H:%M:%S%z'), epoch $T0) ==="
  local admitted_seen=0 parse_total=0 dropin_removed=0 last_pf=$T0
  # Tip just before the restart (for trigger 5: no advance in 10 min).
  local TIP_T0
  TIP_T0=$(journalctl --user -u "$UNIT" --no-pager --since "@$((T0 - 1800))" --until "@$T0" 2>/dev/null \
    | grep -oE 'best_full_block_height=[0-9]+' | tail -1 | grep -oE '[0-9]+$' || echo 0)
  log "tip at T0 (pre-restart): ${TIP_T0:-0}"
  local t1=0 t2=0 t4=0 t5=0 t6=0
  local deadline=$((T0 + 960))   # T0+16 min

  while :; do
    local n; n=$(now_s)
    [ "$n" -ge "$deadline" ] && break

    # --- trigger 3: log EVERY 'handshake not admitted' line with its
    # --- error= reason code (required by the doc, trigger or not), and
    # --- act on the codec signature.
    local adm_count adm_new
    adm_count=$(journal_since "@$T0" | grep -c 'handshake not admitted' || true)
    if [ "${adm_count:-0}" -gt "${admitted_seen:-0}" ]; then
      adm_new=$(journal_since "@$T0" | grep 'handshake not admitted' | tail -n "$((adm_count - admitted_seen))")
      while IFS= read -r line; do
        local code
        code=$(printf '%s' "$line" | grep -oE 'error="[^"]*"' | head -1 | sed 's/error="//; s/"$//')
        if [ "$code" = "$TRIGGER3A" ]; then
          log "ROLLBACK-TRIGGER #3 reason=self-connection-via-session-id line=[$line]"
          do_rollback 3
          exit 42
        fi
        log "admission-denied reason-code='${code:-<none>}' line=[$line] (connection-management, not a rollback trigger)"
      done <<<"$adm_new"
      admitted_seen=$adm_count
    fi

    # --- trigger 3(b): parse-failure burst at the debug target.
    # Burst = >= PARSE_BURST_THRESHOLD parse failures in any 60 s window;
    # each occurrence is logged (incremental scan, no re-logging).
    local pf_recent pf_lines
    pf_recent=$(journal_since "@$((n - 60))" | grep 'handshake failed' | grep -c 'parse handshake' || true)
    pf_recent=${pf_recent:-0}
    pf_lines=$(journal_since "@$last_pf" | grep 'handshake failed' | grep 'parse handshake' || true)
    if [ -n "$pf_lines" ]; then
      while IFS= read -r line; do
        log "PARSE-FAILURE (debug) line=[$line]"
      done <<<"$pf_lines"
      parse_total=$((parse_total + $(printf '%s\n' "$pf_lines" | grep -c .)))
    fi
    last_pf=$n
    if [ "$pf_recent" -ge "$PARSE_BURST_THRESHOLD" ]; then
      log "ROLLBACK-TRIGGER #3 reason=parse-failure-burst count=$pf_recent/60s"
      do_rollback 3
      exit 42
    fi

    # --- checkpoint triggers (evaluated once each, at their due time).
    local peers bans tip gap health
    peers=$(latest_field peers); peers=${peers:-0}
    bans=$(latest_field bans); bans=${bans:-0}
    tip=$(latest_field best_full_block_height); tip=${tip:-0}
    gap=$(latest_field gap); gap=${gap:-0}
    health=$(latest_storage_health); health=${health:-unknown}

    if [ "$t1" = 0 ] && [ "$n" -ge $((T0 + 180)) ]; then
      t1=1
      local act; act=$(systemctl --user is-active "$UNIT" || true)
      local gauges; gauges=$(journal_since "@$T0" | grep -c 'node_gauges' || true)
      if [ "$act" != "active" ] || [ "${gauges:-0}" -eq 0 ]; then
        log "ROLLBACK-TRIGGER #1 reason=service-state active=$act gauges_since_T0=$gauges"
        do_rollback 1; exit 42
      fi
      log "trigger 1 check OK (T0+3m): active=$act gauges_since_T0=$gauges peers=$peers"
    fi

    if [ "$t2" = 0 ] && [ "$n" -ge $((T0 + 300)) ]; then
      t2=1
      if [ "$peers" -lt 20 ]; then
        log "ROLLBACK-TRIGGER #2 reason=peer-recovery peers=$peers<20 (baseline ~65 by T0+2m)"
        do_rollback 2; exit 42
      fi
      log "trigger 2 check OK (T0+5m): peers=$peers bans=$bans"
    fi

    if [ "$dropin_removed" = 0 ] && [ "$n" -ge $((T0 + 600)) ]; then
      dropin_removed=1
      rm -f "$DROPIN"
      systemctl --user daemon-reload
      log "debug window closed at T0+10m (drop-in removed; the running process keeps RUST_LOG until its next restart — peer_loop debug volume is failure-path only)"
    fi

    if [ "$t4" = 0 ] && [ "$n" -ge $((T0 + 600)) ]; then
      t4=1
      if [ "$bans" -ge 2 ] && [ "$peers" -lt 40 ]; then
        log "ROLLBACK-TRIGGER #4 reason=ban-wave bans=$bans>=2 peers=$peers<40"
        do_rollback 4; exit 42
      fi
      log "trigger 4 check OK (T0+10m): bans=$bans peers=$peers"
    fi

    if [ "$t5" = 0 ] && [ "$n" -ge $((T0 + 600)) ]; then
      t5=1
      local bad_hb
      bad_hb=$(journal_since "@$T0" | grep 'node_heartbeat' | tail -6 \
        | grep -cE ' gap=[1-9]|storage_health="[^h]"' || true)
      if [ "$tip" -le "$TIP_T0" ] || [ "${bad_hb:-0}" -ge 5 ]; then
        log "ROLLBACK-TRIGGER #5 reason=tip-stall-or-storage tip_T0=$TIP_T0 tip_now=$tip bad_heartbeats_6=${bad_hb:-0} gap=$gap health=$health"
        do_rollback 5; exit 42
      fi
      log "trigger 5 check OK (T0+10m): tip $TIP_T0 -> $tip gap=$gap health=$health"
    fi

    if [ "$t6" = 0 ] && [ "$n" -ge $((T0 + 900)) ]; then
      t6=1
      local pmin pmax
      local vals; vals=$(journal_since "@$((n - 300))" | grep 'node_gauges' | grep -oE '(^| )peers=[0-9]+' | grep -oE '[0-9]+$' | tr '\n' ' ')
      if [ -n "${vals// /}" ]; then
        pmin=$(printf '%s\n' $vals | sort -n | head -1)
        pmax=$(printf '%s\n' $vals | sort -n | tail -1)
        # oscillating ±20% in the 5-min window (only meaningful once
        # recovered: peers>40 is trigger 2's recovered baseline)
        if [ "$pmax" -ge 20 ] && [ $(( (pmax - pmin) * 10 )) -ge $(( pmax * 2 )) ]; then
          log "ROLLBACK-TRIGGER #6 reason=churn 5m-window peers min=$pmin max=$pmax (±20%)"
          do_rollback 6; exit 42
        fi
        log "trigger 6 check OK (T0+15m): 5m-window peers min=$pmin max=$pmax"
      else
        log "trigger 6 check: no gauge samples in the last 5 m (service may be down — trigger 1 will catch it)"
      fi
    fi

    sleep 10
  done

  log "=== MONITOR complete (T0+16m): no rollback triggers fired; parse-failures total=$parse_total admission-denied total=$admitted_seen ==="
  log "proceed with 'swap-observe' (step 3)"
}

# ----------------------------------------------------------- swap-observe ---
cmd_swap_observe() {
  verify_staged
  log "=== SWAP-OBSERVE (step 3) start ==="
  systemctl --user stop "$OBS_UNIT" "$CRW_UNIT" "$CRWT_UNIT"
  log "stopped observer + crawlers"
  local pair
  for pair in "$OBS_DIR/observer:$STAGE/observer:$EXP_OBSERVER" \
              "$CRW_DIR/crawler:$STAGE/crawler:$EXP_CRAWLER" \
              "$CRWT_DIR/crawler:$STAGE/crawler:$EXP_CRAWLER"; do
    local target=${pair%%:*}; rest=${pair#*:}
    local src=${rest%%:*}; exp=${rest#*:}
    local dir; dir=$(dirname "$target")
    install -m 755 "$src" "$dir/.new-swap"
    mv -f "$dir/.new-swap" "$target"
    [ "$(sha "$target")" = "$exp" ] || die "post-swap hash mismatch for $target"
    log "swapped $target sha256=$(sha "$target")"
  done
  systemctl --user start "$OBS_UNIT" "$CRW_UNIT" "$CRWT_UNIT"
  sleep 2
  for u in "$OBS_UNIT" "$CRW_UNIT" "$CRWT_UNIT"; do
    local t; t=$(systemctl --user show -p ActiveEnterTimestamp --value "$u")
    log "started $u at $t (dataset boundary: mono_ns session break in that stream)"
  done
  log "=== SWAP-OBSERVE done ==="
}

# -------------------------------------------------------------- rollback ----
do_rollback() { # $1 = trigger number
  local trig=${1:-manual}
  log "ROLLBACK (trigger #$trig): restoring pre-phase-0 state"
  systemctl --user stop "$UNIT" || log "WARN: stop failed (service may already be down)"
  # Newest backup of each kind (from cmd_backup).
  local bbin btoml
  bbin=$(ls -1t "$BKS"/ergo-node.* 2>/dev/null | grep -v toml | head -1)
  btoml=$(ls -1t "$BKS"/ergo-node.toml.* 2>/dev/null | head -1)
  [ -n "$bbin" ] || die "no ergo-node backup found in $BKS"
  [ -n "$btoml" ] || die "no ergo-node.toml backup found in $BKS"
  log "restoring $bbin and $btoml"
  cp -p "$bbin" "$NODE_BIN"
  cp -p "$btoml" "$NODE_TOML"
  rm -f "$DROPIN"
  systemctl --user daemon-reload
  systemctl --user start "$UNIT"
  log "restarted $UNIT with restored binaries at $(date '+%Y-%m-%dT%H:%M:%S%z'); verifying for 3 min"
  local ok_api=0 ok_peers=0
  for _ in $(seq 1 18); do
    sleep 10
    curl -s --max-time 5 -o /dev/null 127.0.0.1:9063/api/v1/info && ok_api=1
    local p; p=$(T0=0; latest_field peers); p=${p:-0}
    [ "$p" -gt 40 ] && ok_peers=1
    [ "$ok_api" = 1 ] && [ "$ok_peers" = 1 ] && break
  done
  local b; b=$(T0=0; latest_field bans); b=${b:-0}
  local adm; adm=$(journal_since "1 min ago" | grep -c 'handshake not admitted' || true)
  if [ "$ok_api" = 1 ] && [ "$ok_peers" = 1 ] && [ "${b:-0}" = 0 ] && [ "${adm:-0}" = 0 ]; then
    log "ROLLBACK verified: api up, peers>40, bans=0, no admission denials. STEP 3 IS HELD if trigger was #3; record T0 and this time in the redeploy table and the dataset note."
  else
    log "ROLLBACK verification INCOMPLETE: api=$ok_api peers_ok=$ok_peers bans=${b:-?} recent_admission_denials=${adm:-?} — investigate manually before any further step"
  fi
}
cmd_rollback() { do_rollback manual; }

# ---------------------------------------------------------------- status ----
cmd_status() {
  T0=0
  echo "unit states:"
  for u in "$UNIT" "$OBS_UNIT" "$CRW_UNIT" "$CRWT_UNIT"; do
    printf '  %-28s %s\n' "$u" "$(systemctl --user is-active "$u" 2>/dev/null || echo unknown)"
  done
  printf 'latest: peers=%s bans=%s tip=%s gap=%s health=%s\n' \
    "$(latest_field peers)" "$(latest_field bans)" \
    "$(latest_field best_full_block_height)" "$(latest_field gap)" \
    "$(latest_storage_health)"
  echo "handshake not admitted (last 24 h): $(journalctl --user -u "$UNIT" --since '24 hours ago' --no-pager 2>/dev/null | grep -c 'handshake not admitted' || true)"
  echo "log: $LOG"
}

case "${1:-}" in
  backup) cmd_backup ;;
  swap-node) cmd_swap_node ;;
  monitor) shift; cmd_monitor "$@" ;;
  swap-observe) cmd_swap_observe ;;
  rollback) cmd_rollback ;;
  status) cmd_status ;;
  *) echo "usage: $0 {backup|swap-node|monitor [epoch]|swap-observe|rollback|status}"; exit 2 ;;
esac
