#!/bin/bash
# High-concurrency log fetcher for running Tyche experiments.
set -euo pipefail

RUN_DIR="${1:-benchmark/runs/.aws_n64_e200.running}"
MAX_JOBS="${2:-64}"

STATE_FILE="$RUN_DIR/aws_state.env"
CONFIG_FILE="$RUN_DIR/run_config.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "ERROR: state file not found: $STATE_FILE"
  exit 1
fi

source "$STATE_FILE"
N="${N//$'\r'/}"

PROTO=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['protocols'][0])" 2>/dev/null || echo "tyche-reconfig")
REMOTE_DIR="${REMOTE_DIR:-TycheBench}"
REMOTE_DIR="${REMOTE_DIR//$'\r'/}"
SSH_KEY="/c/Users/kanla/.ssh/AWS-Hou.pem"
if [[ ! -f "$SSH_KEY" && -f "/mnt/c/Users/kanla/.ssh/AWS-Hou.pem" ]]; then
  SSH_KEY="/mnt/c/Users/kanla/.ssh/AWS-Hou.pem"
fi
KNOWN_HOSTS="/tmp/tyche_fetch_known_hosts_$$"
TMP_KEY=""
if [[ "$SSH_KEY" == /mnt/c/* || "$SSH_KEY" == /c/* ]]; then
  TMP_KEY="/tmp/tyche_fetch_key_$$.pem"
  cp "$SSH_KEY" "$TMP_KEY"
  chmod 600 "$TMP_KEY"
  SSH_KEY="$TMP_KEY"
fi

LOCAL_LOG_DIR="$RUN_DIR/runlogs/$PROTO"
mkdir -p "$LOCAL_LOG_DIR"

echo "=== Fetching logs: N=$N proto=$PROTO remote=~/$REMOTE_DIR/runlogs/$PROTO ==="
echo "=== Key: $SSH_KEY ==="
echo "=== Local: $LOCAL_LOG_DIR ==="
echo "=== Max concurrent: $MAX_JOBS ==="
echo ""

fetch_one() {
  local node="$1"
  local ip_var="SERVER_${node}_IP"
  local ip="${!ip_var}"
  ip="${ip//$'\r'/}"
  local remote_path="$REMOTE_DIR/runlogs/$PROTO/node${node}.log"
  local local_path="$LOCAL_LOG_DIR/node${node}.log"
  local errfile="/tmp/fetch_err_$$_${node}.log"

  if scp -o StrictHostKeyChecking=no \
         -o ConnectTimeout=10 \
         -o ServerAliveInterval=10 \
         -o ServerAliveCountMax=3 \
         -o UserKnownHostsFile="$KNOWN_HOSTS" \
         -i "$SSH_KEY" \
         "ubuntu@$ip:~/$remote_path" "$local_path" 2>"$errfile"; then
    local size
    size=$(wc -c < "$local_path" 2>/dev/null || echo 0)
    echo "[OK] node$node ($ip) - ${size} bytes"
  else
    local err
    err=$(tail -3 "$errfile" 2>/dev/null | tr '\n' ' ' || echo "unknown error")
    echo "[FAIL] node$node ($ip) - $err"
  fi
  rm -f "$errfile"
}

export -f fetch_one
export SSH_KEY KNOWN_HOSTS REMOTE_DIR PROTO LOCAL_LOG_DIR

: > "$KNOWN_HOSTS"

count=0
for ((i=0; i<N; i++)); do
  ip_var="SERVER_${i}_IP"
  if [[ -z "${!ip_var:-}" ]]; then
    echo "[SKIP] node$i - no IP found"
    continue
  fi
  fetch_one "$i" &
  count=$((count + 1))
  if (( count % MAX_JOBS == 0 )); then
    wait
  fi
done
wait

echo ""
echo "=== Done ==="
fetched=$(ls -1 "$LOCAL_LOG_DIR"/*.log 2>/dev/null | wc -l)
echo "=== Fetched $fetched / $N log files to $LOCAL_LOG_DIR ==="
echo ""
echo "=== File sizes ==="
ls -lhS "$LOCAL_LOG_DIR" 2>/dev/null | head -20
rm -f "$TMP_KEY" "$KNOWN_HOSTS"
