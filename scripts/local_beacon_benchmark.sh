#!/usr/bin/env bash
set -Eeuo pipefail

N="${N:-8}"
EPOCHS="${EPOCHS:-1000}"
F="${F:-$(((N - 1) / 3))}"
QUEUE_LEN="${QUEUE_LEN:-8}"
PRODUCER_MS="${PRODUCER_MS:-250}"
PREFILL_MS="${PREFILL_MS:-3000}"
EPOCH_TIMEOUT_MS="${EPOCH_TIMEOUT_MS:-15000}"
REPORT_MS="${REPORT_MS:-5000}"
MAX_POOL="${MAX_POOL:-4}"
AGGREGATION_LOOKAHEAD="${AGGREGATION_LOOKAHEAD:-8}"
GOMAXPROCS_LOCAL="${GOMAXPROCS_LOCAL:-4}"
PROTOCOLS="${PROTOCOLS:-tyche,tyche-reconfig,asyrand,grandline,spurt}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${OUT_ROOT:-$REPO_ROOT/benchmark/runs/local_m1n${N}_$(date +%Y%m%d_%H%M%S)}"
GEN_DIR="$OUT_ROOT/generated"
BENCH_TMP="${BENCH_TMP:-${TMPDIR:-/tmp}}"

split_csv() {
  local raw="$1" out_name="$2" old_ifs="$IFS"
  IFS=',' read -r -a "$out_name" <<< "$raw"
  IFS="$old_ifs"
}

ensure_asyrand_config() {
  local src="$REPO_ROOT/spurt/configs/local_8_rounds_1000.json"
  local dst="$GEN_DIR/asyrand_local_${N}_rounds_${EPOCHS}.json"
  mkdir -p "$GEN_DIR"
  sed \
    -e 's/"protocol": "spurt-v1"/"protocol": "asyrand-v1"/' \
    -e "s/\"round\": [0-9][0-9]*/\"round\": $EPOCHS/" \
    -e "s/\"queue_len\": [0-9][0-9]*/\"queue_len\": $QUEUE_LEN/" \
    -e "s/\"producer_interval_ms\": [0-9][0-9]*/\"producer_interval_ms\": $PRODUCER_MS/" \
    -e "s/\"prefill_ms\": [0-9][0-9]*/\"prefill_ms\": $PREFILL_MS/" \
    -e "s/\"epoch_timeout_ms\": [0-9][0-9]*/\"epoch_timeout_ms\": $EPOCH_TIMEOUT_MS/" \
    -e "s/\"report_interval_ms\": [0-9][0-9]*/\"report_interval_ms\": $REPORT_MS/" \
    -e "s/\"aggregation_lookahead\": [0-9][0-9]*/\"aggregation_lookahead\": $AGGREGATION_LOOKAHEAD/" \
    -e "s/\"max_pool\": [0-9][0-9]*/\"max_pool\": $MAX_POOL/" \
    "$src" > "$dst"
  printf '%s\n' "$dst"
}

config_from_template() {
  local proto="$1" src="$2" dst="$GEN_DIR/${proto}_local_${N}_rounds_${EPOCHS}.json"
  mkdir -p "$GEN_DIR"
  sed \
    -e "s/\"round\": [0-9][0-9]*/\"round\": $EPOCHS/" \
    -e "s/\"queue_len\": [0-9][0-9]*/\"queue_len\": $QUEUE_LEN/" \
    -e "s/\"producer_interval_ms\": [0-9][0-9]*/\"producer_interval_ms\": $PRODUCER_MS/" \
    -e "s/\"prefill_ms\": [0-9][0-9]*/\"prefill_ms\": $PREFILL_MS/" \
    -e "s/\"epoch_timeout_ms\": [0-9][0-9]*/\"epoch_timeout_ms\": $EPOCH_TIMEOUT_MS/" \
    -e "s/\"report_interval_ms\": [0-9][0-9]*/\"report_interval_ms\": $REPORT_MS/" \
    -e "s/\"aggregation_lookahead\": [0-9][0-9]*/\"aggregation_lookahead\": $AGGREGATION_LOOKAHEAD/" \
    -e "s/\"max_pool\": [0-9][0-9]*/\"max_pool\": $MAX_POOL/" \
    "$src" > "$dst"
  printf '%s\n' "$dst"
}

run_protocol() {
  local proto="$1" run_dir="$OUT_ROOT/$proto" logf="$OUT_ROOT/$proto/local.log" cfg
  mkdir -p "$run_dir"
  case "$proto" in
    tyche)
      (cd "$REPO_ROOT/Tyche" && GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/tyche -n "$N" -f "$F" -epochs "$EPOCHS" -transport memory -queue-len "$QUEUE_LEN" -producer-ms "$PRODUCER_MS" -prefill-ms "$PREFILL_MS" -epoch-timeout-ms "$EPOCH_TIMEOUT_MS" -report-ms "$REPORT_MS" -max-pool "$MAX_POOL") > "$logf" 2>&1
      ;;
    tyche-reconfig)
      (cd "$REPO_ROOT/Tyche" && TYCHE_RECONFIG_BENCH_TEST=1 TYCHE_CHURN_EPOCHS="$EPOCHS" TYCHE_CHURN_RECONFIG_EVENTS="${TYCHE_RECONFIG_EVENTS:-$((EPOCHS / 20))}" TYCHE_CHURN_MIN_N="${TYCHE_RECONFIG_MIN_N:-4}" TYCHE_CHURN_MAX_N="${TYCHE_RECONFIG_MAX_N:-13}" TYCHE_CHURN_EPOCH_TIMEOUT_MS="$EPOCH_TIMEOUT_MS" TYCHE_CHURN_SEED="${TYCHE_RECONFIG_SEED:-20260521}" GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go test ./protocol/tyche -run TestBeaconReconfigurationBenchmark200Epochs -count=1 -v) > "$logf" 2>&1
      ;;
    asyrand)
      cfg="$(ensure_asyrand_config)"
      (cd "$REPO_ROOT/asyrand" && GOCACHE="$BENCH_TMP/asyrand-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/asyrand -config "$cfg" -transport memory) > "$logf" 2>&1
      ;;
    grandline)
      cfg="$(config_from_template grandline "$REPO_ROOT/grandline/configs/local_8_rounds_1000.json")"
      (cd "$REPO_ROOT/grandline" && GOCACHE="$BENCH_TMP/grandline-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/grandline -config "$cfg" -transport memory) > "$logf" 2>&1
      ;;
    spurt)
      cfg="$(config_from_template spurt "$REPO_ROOT/spurt/configs/local_8_rounds_1000.json")"
      (cd "$REPO_ROOT/spurt" && GOCACHE="$BENCH_TMP/spurt-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/spurt -config "$cfg" -transport memory) > "$logf" 2>&1
      ;;
    *)
      printf 'unknown protocol: %s\n' "$proto" >&2
      return 1
      ;;
  esac
}

parse_results() {
  local csv="$OUT_ROOT/results.csv" breakdown="$OUT_ROOT/phase_crypto_breakdown.csv" proto logf final thr bw sent_msgs recv_msgs real user sys cpu_pct
  printf 'protocol,node,host,region,ip,throughput_beacon_min,throughput_beacon_s,bandwidth_kbps,cpu_percent,sent_msgs,recv_msgs,log\n' > "$csv"
  printf 'protocol,node,host,region,ip,crypto_share_avg,crypto_verify_avg,crypto_recon_avg,crypto_sign_avg,crypto_aggregate_avg,agreement_avg,rbc_avg,aba_avg,log\n' > "$breakdown"
  for proto in "${PROTOCOLS_LIST[@]}"; do
    logf="$OUT_ROOT/$proto/local.log"
    final="$(grep 'final metrics' "$logf" | tail -n 1 || true)"
    if [[ -z "$final" ]]; then
      printf 'missing final metrics: %s\n' "$logf" >&2
      tail -n 80 "$logf" >&2 || true
      return 1
    fi
    thr="$(grep -o 'throughput=[0-9.]*' <<< "$final" | cut -d= -f2)"
    bw="$(grep -o 'bandwidth=[0-9.]*' <<< "$final" | cut -d= -f2)"
    sent_msgs="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^sent_msgs=[0-9]+$/) {sub(/^sent_msgs=/,"",$i); print $i; exit}}' <<< "$final")"
    recv_msgs="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^recv_msgs=[0-9]+$/) {sub(/^recv_msgs=/,"",$i); print $i; exit}}' <<< "$final")"
    real="$(awk '/^real / {print $2}' "$logf" | tail -n 1)"
    user="$(awk '/^user / {print $2}' "$logf" | tail -n 1)"
    sys="$(awk '/^sys / {print $2}' "$logf" | tail -n 1)"
    cpu_pct="$(awk -v u="$user" -v s="$sys" -v e="$real" 'BEGIN { if (e<=0) e=1; printf "%.2f", (u+s)/e*100 }')"
    printf '%s,local,host0,local,127.0.0.1,%s,%.4f,%s,%s,%s,%s,%s\n' \
      "$proto" "$thr" \
      "$(awk -v t="$thr" 'BEGIN {printf "%.4f", t/60}')" \
      "$bw" "$cpu_pct" "$sent_msgs" "$recv_msgs" "$logf" >> "$csv"
    write_breakdown_row "$breakdown" "$proto" "local" "host0" "local" "127.0.0.1" "$final" "$logf"
  done
  write_breakdown_notes
  write_final_metrics_log
}

metric_value() {
  local final="$1" key="$2" value
  value="$(awk -v key="$key" '{
    prefix=key "="
    for (i=1;i<=NF;i++) {
      if (index($i, prefix) == 1) {
        sub(prefix, "", $i)
        print $i
        exit
      }
    }
  }' <<< "$final")"
  printf '%s' "${value:-0}"
}

write_breakdown_row() {
  local csv="$1" proto="$2" node="$3" host="$4" region="$5" ip="$6" final="$7" logf="$8"
  local share verify recon sign aggregate agreement rbc aba
  share="$(metric_value "$final" "pvss_share_avg")"
  verify="$(metric_value "$final" "pvss_verify_avg")"
  recon="$(metric_value "$final" "pvss_recon_avg")"
  sign="$(metric_value "$final" "sign_avg")"
  if [[ "$sign" == "0" ]]; then
    sign="$(metric_value "$final" "bls_sign_avg")"
  fi
  aggregate="$(metric_value "$final" "bls_agg_avg")"
  agreement="$(metric_value "$final" "spurt_vote_avg")"
  rbc="$(metric_value "$final" "rbc_avg")"
  aba="$(metric_value "$final" "aba_avg")"
  if [[ "$verify" == "0" ]]; then
    verify="$(metric_value "$final" "verify_avg")"
  fi
  if [[ "$recon" == "0" ]]; then
    recon="$(metric_value "$final" "recover_avg")"
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$proto" "$node" "$host" "$region" "$ip" "$share" "$verify" "$recon" "$sign" "$aggregate" "$agreement" "$rbc" "$aba" "$logf" >> "$csv"
}

write_breakdown_notes() {
  cat > "$OUT_ROOT/breakdown_notes.md" <<'EOF'
# Crypto/Phase Breakdown

`phase_crypto_breakdown.csv` reports per-operation average costs aggregated over all nodes and all epochs in a run. These values are not per-node per-epoch latency. They are intended to explain which cryptographic or protocol phase dominates a protocol implementation.

Fields:
- `crypto_share_avg`: average PVSS share generation time.
- `crypto_verify_avg`: average PVSS commitment/share verification time, or signature verification time for protocols without PVSS.
- `crypto_recon_avg`: average PVSS reconstruction or threshold-signature recovery time.
- `crypto_sign_avg`: average signature-share generation time.
- `crypto_aggregate_avg`: average threshold/BLS aggregation time.
- `agreement_avg`: average explicit agreement-step handling time when the protocol exports one.
- `rbc_avg`: average reliable-broadcast handling time.
- `aba_avg`: average asynchronous-binary-agreement handling time.

Interpretation guide:
- Tyche should be read together with `message_type` lines in each log. High `aba_sent_msgs` or `aba_msg_pct` indicates ABA/RBC message amplification.
- AsyRand is expected to show lightweight PVSS and RBC costs; remaining bottlenecks usually come from BLS verification/aggregation and scheduling.
- GRandLine usually has low message count and bandwidth; its bottleneck is often signature verification/recovery.
- SPURT uses pre-aggregation to move leader aggregation off the critical path, but PVSS sharing and reconstruction remain total-work bottlenecks.
EOF
}

write_final_metrics_log() {
  local out="$OUT_ROOT/final_metrics.log" proto logf
  : > "$out"
  for proto in "${PROTOCOLS_LIST[@]}"; do
    logf="$OUT_ROOT/$proto/local.log"
    [[ -f "$logf" ]] || continue
    awk -v proto="$proto" -v node="local" -v host="host0" -v region="local" -v ip="127.0.0.1" '
      /bench_result|final metrics|compare|message_type/ {
        printf "protocol=%s node=%s host=%s region=%s ip=%s %s\n", proto, node, host, region, ip, $0
      }
    ' "$logf" >> "$out"
  done
}

main() {
  mkdir -p "$OUT_ROOT"
  split_csv "$PROTOCOLS" PROTOCOLS_LIST
  for proto in "${PROTOCOLS_LIST[@]}"; do
    printf '[%s] running %s n=%s epochs=%s max_pool=%s\n' "$(date '+%H:%M:%S')" "$proto" "$N" "$EPOCHS" "$MAX_POOL"
    run_protocol "$proto"
  done
  parse_results
  printf 'results: %s\n' "$OUT_ROOT/results.csv"
}

main "$@"
