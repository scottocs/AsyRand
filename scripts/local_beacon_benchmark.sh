#!/usr/bin/env bash
set -Eeuo pipefail

N="${N:-8}"
EPOCHS="${EPOCHS:-1000}"
F="${F:-$(((N - 1) / 3))}"
GRANDLINE_F="${GRANDLINE_F:-$(((N - 1) / 2))}"
QUEUE_LEN="${QUEUE_LEN:-8}"
PRODUCER_MS="${PRODUCER_MS:-50}"
PREFILL_MS="${PREFILL_MS:-3000}"
EPOCH_TIMEOUT_MS="${EPOCH_TIMEOUT_MS:-15000}"
REPORT_MS="${REPORT_MS:-5000}"
MAX_POOL="${MAX_POOL:-2}"
AGGREGATION_LOOKAHEAD="${AGGREGATION_LOOKAHEAD:-8}"
GOMAXPROCS_LOCAL="${GOMAXPROCS_LOCAL:-8}"
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

seed_for_node() {
  local node="$1"
  printf 'tyche-node-%04d' "$node" | shasum -a 256 | awk '{print $1}'
}

protocol_f() {
  local proto="$1"
  case "$proto" in
    grandline)
      printf '%d' "$GRANDLINE_F"
      ;;
    tyche|tyche-scrape|tyche-reconfig|tyche-scrape-reconfig|asyrand|spurt)
      printf '%d' "$F"
      ;;
    *)
      printf '%d' "$F"
      ;;
  esac
}

generate_json_config() {
  local proto="$1" protocol="$2" dst="$GEN_DIR/${proto}_local_${N}_rounds_${EPOCHS}.json"
  local node comma f
  mkdir -p "$GEN_DIR"
  f="$(protocol_f "$proto")"
  {
    printf '{\n'
    printf '  "name": "local-%d-%d",\n' "$N" "$EPOCHS"
    printf '  "protocol": "%s",\n' "$protocol"
    printf '  "transport": "memory",\n'
    printf '  "f": %d,\n' "$f"
    printf '  "round": %d,\n' "$EPOCHS"
    printf '  "queue_len": %d,\n' "$QUEUE_LEN"
    printf '  "listen_ip": "0.0.0.0",\n'
    printf '  "producer_interval_ms": %d,\n' "$PRODUCER_MS"
    printf '  "prefill_ms": %d,\n' "$PREFILL_MS"
    printf '  "epoch_timeout_ms": %d,\n' "$EPOCH_TIMEOUT_MS"
    printf '  "report_interval_ms": %d,\n' "$REPORT_MS"
    printf '  "linger_ms": 15000,\n'
    printf '  "aggregation_lookahead": %d,\n' "$AGGREGATION_LOOKAHEAD"
    printf '  "batch_size": 1,\n'
    printf '  "max_pool": %d,\n' "$MAX_POOL"
    printf '  "log_level": 1,\n'
    printf '  "seed": "%s",\n' "$(printf '%s-local-%s-%s' "$proto" "$N" "$EPOCHS" | shasum -a 256 | awk '{print $1}')"
    printf '  "cluster_index": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": %d%s\n' "$node" "$node" "$comma"
    done
    printf '  },\n'
    printf '  "cluster_ips": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": "127.0.0.1"%s\n' "$node" "$comma"
    done
    printf '  },\n'
    printf '  "peers_p2p_port": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": %d%s\n' "$node" "$((9000 + node))" "$comma"
    done
    printf '  },\n'
    printf '  "node_key_seed": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": "%s"%s\n' "$node" "$(seed_for_node "$node")" "$comma"
    done
    printf '  }\n'
    printf '}\n'
  } > "$dst"
  printf '%s\n' "$dst"
}

run_protocol() {
  local proto="$1" run_dir="$OUT_ROOT/$proto" logf="$OUT_ROOT/$proto/local.log" cfg
  mkdir -p "$run_dir"
  case "$proto" in
    tyche)
      (cd "$REPO_ROOT/Tyche" && GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/tyche -n "$N" -f "$F" -epochs "$EPOCHS" -transport memory -queue-len "$QUEUE_LEN" -producer-ms "$PRODUCER_MS" -prefill-ms "$PREFILL_MS" -epoch-timeout-ms "$EPOCH_TIMEOUT_MS" -report-ms "$REPORT_MS" -max-pool "$MAX_POOL") > "$logf" 2>&1
      ;;
    tyche-scrape)
      (cd "$REPO_ROOT/Tyche" && GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/tyche -n "$N" -f "$F" -epochs "$EPOCHS" -transport memory -queue-len "$QUEUE_LEN" -producer-ms "$PRODUCER_MS" -prefill-ms "$PREFILL_MS" -epoch-timeout-ms "$EPOCH_TIMEOUT_MS" -report-ms "$REPORT_MS" -max-pool "$MAX_POOL" -pvss scrape) > "$logf" 2>&1
      ;;
    tyche-reconfig)
      (cd "$REPO_ROOT/Tyche" && TYCHE_RECONFIG_BENCH_TEST=1 TYCHE_CHURN_INITIAL_N="$N" TYCHE_CHURN_INITIAL_F="$F" TYCHE_CHURN_EPOCHS="$EPOCHS" TYCHE_CHURN_RECONFIG_EVENTS="${TYCHE_RECONFIG_EVENTS:-$((EPOCHS / 20))}" TYCHE_CHURN_PREFILL_MS="$PREFILL_MS" TYCHE_CHURN_MIN_N="${TYCHE_RECONFIG_MIN_N:-$((N - F))}" TYCHE_CHURN_MAX_N="${TYCHE_RECONFIG_MAX_N:-$((N + F))}" TYCHE_CHURN_EPOCH_TIMEOUT_MS="$EPOCH_TIMEOUT_MS" TYCHE_CHURN_SEED="${TYCHE_RECONFIG_SEED:-20260521}" GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go test ./protocol/tyche -run TestBeaconReconfigurationBenchmark200Epochs -count=1 -timeout "${timeout:-${GO_TEST_TIMEOUT:-10m}}" -v) > "$logf" 2>&1
      ;;
    tyche-scrape-reconfig)
      (cd "$REPO_ROOT/Tyche" && TYCHE_RECONFIG_BENCH_TEST=1 TYCHE_CHURN_PVSS=scrape TYCHE_CHURN_INITIAL_N="$N" TYCHE_CHURN_INITIAL_F="$F" TYCHE_CHURN_EPOCHS="$EPOCHS" TYCHE_CHURN_RECONFIG_EVENTS="${TYCHE_RECONFIG_EVENTS:-$((EPOCHS / 20))}" TYCHE_CHURN_PREFILL_MS="$PREFILL_MS" TYCHE_CHURN_MIN_N="${TYCHE_RECONFIG_MIN_N:-$((N - F))}" TYCHE_CHURN_MAX_N="${TYCHE_RECONFIG_MAX_N:-$((N + F))}" TYCHE_CHURN_EPOCH_TIMEOUT_MS="$EPOCH_TIMEOUT_MS" TYCHE_CHURN_SEED="${TYCHE_RECONFIG_SEED:-20260521}" GOCACHE="$BENCH_TMP/tyche-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go test ./protocol/tyche -run TestBeaconReconfigurationBenchmark200Epochs -count=1 -timeout "${timeout:-${GO_TEST_TIMEOUT:-10m}}" -v) > "$logf" 2>&1
      ;;
    asyrand)
      cfg="$(generate_json_config asyrand asyrand-v1)"
      (cd "$REPO_ROOT/asyrand" && GOCACHE="$BENCH_TMP/asyrand-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/asyrand -config "$cfg" -transport memory) > "$logf" 2>&1
      ;;
    grandline)
      cfg="$(generate_json_config grandline grandline)"
      (cd "$REPO_ROOT/grandline" && GOCACHE="$BENCH_TMP/grandline-go-cache" GOSUMDB=off GOMAXPROCS="$GOMAXPROCS_LOCAL" /usr/bin/time -p go run ./cmd/grandline -config "$cfg" -transport memory) > "$logf" 2>&1
      ;;
    spurt)
      cfg="$(generate_json_config spurt spurt-v1)"
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
    sign="$(metric_value "$final" "cert_sign_avg")"
  fi
  aggregate="$(metric_value "$final" "cert_agg_avg")"
  if [[ "$aggregate" == "0" ]]; then
    aggregate="$(metric_value "$final" "bls_agg_avg")"
  fi
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
- `crypto_aggregate_avg`: average quorum-certificate or threshold-signature aggregation time.
- `agreement_avg`: average explicit agreement-step handling time when the protocol exports one.
- `rbc_avg`: average reliable-broadcast handling time.
- `aba_avg`: average asynchronous-binary-agreement handling time.

Interpretation guide:
- Tyche should be read together with `message_type` lines in each log. High `aba_sent_msgs` or `aba_msg_pct` indicates ABA/RBC message amplification.
- AsyRand is expected to show lightweight PVSS and RBC costs; remaining bottlenecks usually come from certificate handling and scheduling.
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
      /bench_result|final metrics|compare|message_category|message_type/ {
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
