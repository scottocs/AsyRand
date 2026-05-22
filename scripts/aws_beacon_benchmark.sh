#!/usr/bin/env bash
set -Eeuo pipefail

# General AWS benchmark runner for Tyche / AsyRand / GRandLine / SPURT.
#
# Architecture:
#   local source tree -> bastion builds binaries -> bastion distributes runtime
#   to M AWS servers -> N beacon nodes are started across those M servers.
#
# Common usage:
#   M=4 N=8 EPOCHS=200 ./scripts/aws_beacon_benchmark.sh
#   BASTION_IP=1.2.3.4 M=8 N=32 ./scripts/aws_beacon_benchmark.sh
#
# When capacity is insufficient, the script creates EC2 instances in different
# regions where possible, binds an Elastic IP for a fixed public address, and
# uses an instance type with at least 4 vCPU / 4 GiB memory. EC2 networking uses
# the normal pay-as-you-go data transfer model.
#
# Required local tools: aws, ssh, scp, rsync, ping, shasum.
# Required AWS credentials: configured for `aws ec2 ...` in the target regions.

M="${M:-4}"
N="${N:-8}"
EPOCHS="${EPOCHS:-200}"
BFT_F="${F:-$(((N - 1) / 3))}"
GRANDLINE_F="${GRANDLINE_F:-$(((N - 1) / 2))}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6i.xlarge}"
RUN_NAME="${RUN_NAME:-tyche-beacon-$(date +%Y%m%d-%H%M%S)}"
REMOTE_DIR="${REMOTE_DIR:-TycheBench}"
BASE_PORT="${BASE_PORT:-9000}"
PRODUCER_MS="${PRODUCER_MS:-250}"
PREFILL_MS="${PREFILL_MS:-8000}"
EPOCH_TIMEOUT_MS="${EPOCH_TIMEOUT_MS:-60000}"
REPORT_MS="${REPORT_MS:-5000}"
QUEUE_LEN="${QUEUE_LEN:-8}"
LINGER_MS="${LINGER_MS:-120000}"
GOMAXPROCS_REMOTE="${GOMAXPROCS_REMOTE:-4}"
STARTUP_WAIT_SEC="${STARTUP_WAIT_SEC:-}"
RUN_COMMANDS_VIA_BASTION="${RUN_COMMANDS_VIA_BASTION:-0}"
REMOTE_PEM_DIR="${REMOTE_PEM_DIR:-pems}"
BASTION_IP="${BASTION_IP:-}"
BASTION_REGION="${BASTION_REGION:-}"
SSH_USER="${SSH_USER:-}"
KEY_NAME_PREFIX="${KEY_NAME_PREFIX:-tyche-beacon}"
KNOWN_HOSTS="${KNOWN_HOSTS:-/private/tmp/tyche_aws_known_hosts}"
SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-30}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEM_DIR="${PEM_DIR:-$REPO_ROOT/pems}"
OUT_ROOT="${OUT_ROOT:-$REPO_ROOT/benchmarks/aws_m${M}n${N}_$(date +%Y%m%d_%H%M%S)}"
GEN_DIR="$REPO_ROOT/benchmarks/generated_aws_m${M}n${N}"

DEFAULT_REGIONS="us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,eu-west-1,eu-west-2,eu-central-1,eu-north-1,ap-northeast-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-south-1,sa-east-1,me-central-1"
REGIONS_CSV="${REGIONS:-$DEFAULT_REGIONS}"
PROTOCOLS_CSV="${PROTOCOLS:-tyche,asyrand,grandline,spurt}"

REGIONS_LIST=()
PROTOCOLS_LIST=()
SERVER_REGIONS=()
SERVER_IPS=()
SERVER_KEYS=()
SERVER_USERS=()
SERVER_INSTANCE_IDS=()
BASTION_INDEX=-1

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

split_csv() {
  local raw="$1" out_name="$2" old_ifs="$IFS"
  IFS=',' read -r -a "$out_name" <<< "$raw"
  IFS="$old_ifs"
}

wait_all() {
  local failed=0 pid
  for pid in "$@"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done
  return "$failed"
}

startup_wait_seconds() {
  if [[ -n "$STARTUP_WAIT_SEC" ]]; then
    printf '%s' "$STARTUP_WAIT_SEC"
    return 0
  fi
  if (( N >= 128 )); then
    printf '15'
  elif (( N >= 64 )); then
    printf '10'
  else
    printf '5'
  fi
}

ping_once() {
  local ip="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    ping -c 1 -W 2000 "$ip" >/dev/null 2>&1
  else
    ping -c 1 -W 2 "$ip" >/dev/null 2>&1
  fi
}

wait_ping() {
  local ip="$1" tries="${2:-30}" n
  for n in $(seq 1 "$tries"); do
    if ping_once "$ip"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

aws_region() {
  local region="$1"
  shift
  aws ec2 "$@" --region "$region" --no-cli-pager
}

pem_name() {
  local region="$1" ip="$2"
  printf '%s_%s.pem' "$region" "$ip"
}

pem_path() {
  local region="$1" ip="$2"
  printf '%s/%s' "$PEM_DIR" "$(pem_name "$region" "$ip")"
}

add_server() {
  local region="$1" ip="$2" key="$3" instance_id="${4:-}" user="${5:-}"
  local i
  for i in "${!SERVER_IPS[@]}"; do
    [[ "${SERVER_IPS[$i]}" == "$ip" ]] && return 0
  done
  SERVER_REGIONS+=("$region")
  SERVER_IPS+=("$ip")
  SERVER_KEYS+=("$key")
  SERVER_INSTANCE_IDS+=("$instance_id")
  SERVER_USERS+=("$user")
}

swap_server_indexes() {
  local a="$1" b="$2" tmp
  [[ "$a" -eq "$b" ]] && return 0
  tmp="${SERVER_REGIONS[$a]}"; SERVER_REGIONS[$a]="${SERVER_REGIONS[$b]}"; SERVER_REGIONS[$b]="$tmp"
  tmp="${SERVER_IPS[$a]}"; SERVER_IPS[$a]="${SERVER_IPS[$b]}"; SERVER_IPS[$b]="$tmp"
  tmp="${SERVER_KEYS[$a]}"; SERVER_KEYS[$a]="${SERVER_KEYS[$b]}"; SERVER_KEYS[$b]="$tmp"
  tmp="${SERVER_USERS[$a]}"; SERVER_USERS[$a]="${SERVER_USERS[$b]}"; SERVER_USERS[$b]="$tmp"
  tmp="${SERVER_INSTANCE_IDS[$a]}"; SERVER_INSTANCE_IDS[$a]="${SERVER_INSTANCE_IDS[$b]}"; SERVER_INSTANCE_IDS[$b]="$tmp"
}

extract_ip_from_name() {
  local name="$1"
  if [[ "$name" =~ ([0-9]{1,3}\.){3}[0-9]{1,3} ]]; then
    printf '%s' "${BASH_REMATCH[0]}"
  fi
}

extract_region_from_name() {
  local name="$1" ip="$2"
  name="${name%.pem}"
  name="${name%_$ip}"
  name="${name%-$ip}"
  if [[ "$name" == "$ip" || -z "$name" ]]; then
    printf 'unknown'
  else
    printf '%s' "$name"
  fi
}

discover_servers_from_pems() {
  mkdir -p "$PEM_DIR"
  local pem base ip region
  shopt -s nullglob
  for pem in "$PEM_DIR"/*.pem; do
    base="$(basename "$pem")"
    ip="$(extract_ip_from_name "$base")"
    [[ -n "$ip" ]] || continue
    region="$(extract_region_from_name "$base" "$ip")"
    chmod 600 "$pem" 2>/dev/null || true
    add_server "$region" "$ip" "$pem"
  done
  shopt -u nullglob
}

copy_key_to_region_ip_name() {
  local region="$1" ip="$2" source_key="$3"
  local dst
  dst="$(pem_path "$region" "$ip")"
  mkdir -p "$PEM_DIR"
  if [[ -s "$dst" ]]; then
    chmod 600 "$dst"
    printf '%s' "$dst"
    return 0
  fi
  [[ -s "$source_key" ]] || return 1
  cp "$source_key" "$dst"
  chmod 600 "$dst"
  printf '%s' "$dst"
}

find_local_key_for_instance() {
  local region="$1" ip="$2" key_name="$3"
  local key
  key="$(pem_path "$region" "$ip")"
  if [[ -s "$key" ]]; then
    chmod 600 "$key"
    printf '%s' "$key"
    return 0
  fi
  for key in "$PEM_DIR/${key_name}.pem" "$PEM_DIR/${key_name}-${region}.pem" "$PEM_DIR/${region}-${key_name}.pem" "/private/tmp/${key_name}.pem" "/private/tmp/${key_name}-${region}.pem"; do
    if [[ -s "$key" ]]; then
      copy_key_to_region_ip_name "$region" "$ip" "$key"
      return 0
    fi
  done
  return 1
}

find_local_key_by_key_name() {
  local region="$1" key_name="$2" key
  for key in "$PEM_DIR/${key_name}.pem" "$PEM_DIR/${key_name}-${region}.pem" "$PEM_DIR/${region}-${key_name}.pem" "/private/tmp/${key_name}.pem" "/private/tmp/${key_name}-${region}.pem"; do
    if [[ -s "$key" ]]; then
      chmod 600 "$key"
      printf '%s' "$key"
      return 0
    fi
  done
  return 1
}

discover_running_aws_servers() {
  local region rows line iid ip key key_path
  for region in "${REGIONS_LIST[@]:0:16}"; do
    rows="$(aws_region "$region" describe-instances \
      --filters 'Name=instance-state-name,Values=running' \
      --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,KeyName]' \
      --output text 2>/dev/null || true)"
    [[ -n "$rows" ]] || continue
    while read -r iid ip key; do
      [[ -n "${iid:-}" && -n "${ip:-}" && "$ip" != "None" ]] || continue
      if key_path="$(find_local_key_for_instance "$region" "$ip" "${key:-}")"; then
        add_server "$region" "$ip" "$key_path" "$iid"
      fi
    done <<< "$rows"
  done
}

start_stopped_aws_servers() {
  local region rows iid ip key key_path final_key
  for region in "${REGIONS_LIST[@]:0:16}"; do
    (( ${#SERVER_IPS[@]} >= M )) && break
    rows="$(aws_region "$region" describe-instances \
      --filters 'Name=instance-state-name,Values=stopped' \
      --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,KeyName]' \
      --output text 2>/dev/null || true)"
    [[ -n "$rows" ]] || continue
    while read -r iid ip key; do
      (( ${#SERVER_IPS[@]} >= M )) && break
      [[ -n "${iid:-}" ]] || continue
      key_path=""
      if [[ -n "${ip:-}" && "$ip" != "None" ]]; then
        key_path="$(find_local_key_for_instance "$region" "$ip" "${key:-}" || true)"
      fi
      if [[ -z "$key_path" ]]; then
        key_path="$(find_local_key_by_key_name "$region" "${key:-}" || true)"
      fi
      if [[ -z "$key_path" ]]; then
        log "skipping stopped instance without local key region=$region instance=$iid key=${key:-}"
        continue
      fi
      log "starting stopped AWS server region=$region instance=$iid"
      aws_region "$region" start-instances --instance-ids "$iid" >/dev/null
      aws_region "$region" wait instance-running --instance-ids "$iid"
      ip="$(aws_region "$region" describe-instances \
        --instance-ids "$iid" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text)"
      [[ -n "$ip" && "$ip" != "None" ]] || { log "started instance has no public ip region=$region instance=$iid"; continue; }
      if ! wait_ping "$ip" 24; then
        log "started instance is not reachable by ping region=$region instance=$iid ip=$ip"
        continue
      fi
      final_key="$(copy_key_to_region_ip_name "$region" "$ip" "$key_path")"
      add_server "$region" "$ip" "$final_key" "$iid"
    done <<< "$rows"
  done
}

choose_bastion() {
  local i
  if [[ -n "$BASTION_IP" ]]; then
    ping_once "$BASTION_IP" || die "BASTION_IP=$BASTION_IP is not reachable by local ping"
    for i in "${!SERVER_IPS[@]}"; do
      if [[ "${SERVER_IPS[$i]}" == "$BASTION_IP" ]]; then
        BASTION_INDEX="$i"
        return 0
      fi
    done
    if [[ -n "$BASTION_REGION" ]]; then
      local key
      key="$(pem_path "$BASTION_REGION" "$BASTION_IP")"
      [[ -s "$key" ]] || die "missing bastion pem: $key"
      add_server "$BASTION_REGION" "$BASTION_IP" "$key"
      BASTION_INDEX=$((${#SERVER_IPS[@]} - 1))
      return 0
    fi
    die "BASTION_IP=$BASTION_IP is reachable, but no matching pem was found in $PEM_DIR; set BASTION_REGION or add ${BASTION_REGION:-region}_${BASTION_IP}.pem"
  fi

  for i in "${!SERVER_IPS[@]}"; do
    if ping_once "${SERVER_IPS[$i]}"; then
      BASTION_INDEX="$i"
      BASTION_IP="${SERVER_IPS[$i]}"
      return 0
    fi
  done
  return 1
}

latest_ubuntu_ami() {
  local region="$1"
  aws_region "$region" describe-images \
    --owners amazon \
    --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*' 'Name=state,Values=available' \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
    --output text
}

default_vpc() {
  local region="$1"
  aws_region "$region" describe-vpcs \
    --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text
}

default_subnet() {
  local region="$1"
  aws_region "$region" describe-subnets \
    --filters Name=default-for-az,Values=true \
    --query 'Subnets[0].SubnetId' --output text
}

ensure_security_group() {
  local region="$1" group="$KEY_NAME_PREFIX-bench" vpc sg
  sg="$(aws_region "$region" describe-security-groups \
    --filters "Name=group-name,Values=$group" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
  if [[ -z "$sg" || "$sg" == "None" ]]; then
    vpc="$(default_vpc "$region")"
    [[ -n "$vpc" && "$vpc" != "None" ]] || die "no default VPC in region=$region"
    sg="$(aws_region "$region" create-security-group \
      --group-name "$group" \
      --description "Tyche beacon benchmark" \
      --vpc-id "$vpc" \
      --query GroupId --output text)"
  fi
  aws_region "$region" authorize-security-group-ingress \
    --group-id "$sg" \
    --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description=ssh}]" >/dev/null 2>&1 || true
  aws_region "$region" authorize-security-group-ingress \
    --group-id "$sg" \
    --ip-permissions "IpProtocol=tcp,FromPort=$BASE_PORT,ToPort=$((BASE_PORT + N + 32)),IpRanges=[{CidrIp=0.0.0.0/0,Description=beacon-peers}]" >/dev/null 2>&1 || true
  aws_region "$region" authorize-security-group-ingress \
    --group-id "$sg" \
    --ip-permissions "IpProtocol=icmp,FromPort=8,ToPort=-1,IpRanges=[{CidrIp=0.0.0.0/0,Description=ping}]" >/dev/null 2>&1 || true
  printf '%s' "$sg"
}

create_key_pair() {
  local region="$1" key_name="$KEY_NAME_PREFIX-$region-$(date +%H%M%S)" key_file="$PEM_DIR/$key_name.pem"
  mkdir -p "$PEM_DIR"
  aws_region "$region" create-key-pair \
    --key-name "$key_name" \
    --query KeyMaterial --output text > "$key_file"
  chmod 600 "$key_file"
  printf '%s %s' "$key_name" "$key_file"
}

launch_server() {
  local region="$1" key_row key_name key_file sg ami subnet iid alloc_id assoc_id ip final_key
  read -r key_name key_file <<< "$(create_key_pair "$region")"
  sg="$(ensure_security_group "$region")"
  ami="$(latest_ubuntu_ami "$region")"
  subnet="$(default_subnet "$region")"
  [[ -n "$subnet" && "$subnet" != "None" ]] || die "no default subnet in region=$region"
  log "launching AWS server region=$region type=$INSTANCE_TYPE fixed_ip=elastic-ip billing=pay-as-you-go"
  iid="$(aws_region "$region" run-instances \
    --image-id "$ami" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$key_name" \
    --security-group-ids "$sg" \
    --subnet-id "$subnet" \
    --associate-public-ip-address \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":24,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$RUN_NAME},{Key=Project,Value=Tyche},{Key=Role,Value=beacon-benchmark}]" \
    --query 'Instances[0].InstanceId' --output text)"
  aws_region "$region" wait instance-running --instance-ids "$iid"
  alloc_id="$(aws_region "$region" allocate-address \
    --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$RUN_NAME},{Key=Project,Value=Tyche},{Key=Role,Value=beacon-benchmark}]" \
    --query AllocationId --output text)"
  assoc_id="$(aws_region "$region" associate-address \
    --instance-id "$iid" \
    --allocation-id "$alloc_id" \
    --query AssociationId --output text)"
  ip="$(aws_region "$region" describe-addresses \
    --allocation-ids "$alloc_id" \
    --query 'Addresses[0].PublicIp' \
    --output text)"
  log "associated elastic ip region=$region instance=$iid allocation=$alloc_id association=$assoc_id ip=$ip"
  wait_ping "$ip" 24 || die "new server is not reachable by ping: region=$region ip=$ip"
  final_key="$(copy_key_to_region_ip_name "$region" "$ip" "$key_file")"
  add_server "$region" "$ip" "$final_key" "$iid"
}

region_already_selected() {
  local region="$1" i
  for i in "${!SERVER_REGIONS[@]}"; do
    [[ "${SERVER_REGIONS[$i]}" == "$region" ]] && return 0
  done
  return 1
}

ensure_enough_servers() {
  local attempts_before="${#SERVER_IPS[@]}" region
  if (( attempts_before >= M )); then
    return 0
  fi
  log "available pem-backed servers=$attempts_before, need M=$M; starting stopped servers before creating new ones"
  start_stopped_aws_servers
  if (( ${#SERVER_IPS[@]} >= M )); then
    return 0
  fi
  log "available servers after starting stopped=${#SERVER_IPS[@]}, need M=$M; creating more across regions"
  for region in "${REGIONS_LIST[@]:0:16}"; do
    (( ${#SERVER_IPS[@]} >= M )) && break
    region_already_selected "$region" && continue
    launch_server "$region"
  done
  for region in "${REGIONS_LIST[@]:0:16}"; do
    (( ${#SERVER_IPS[@]} >= M )) && break
    launch_server "$region"
  done
  (( ${#SERVER_IPS[@]} >= M )) || die "not enough AWS servers after provisioning: have=${#SERVER_IPS[@]} need=$M"
}

ssh_opts_direct() {
  local key="$1"
  printf -- '-o StrictHostKeyChecking=no -o UserKnownHostsFile=%s -o ConnectTimeout=%s -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -i %s' "$KNOWN_HOSTS" "$SSH_CONNECT_TIMEOUT" "$key"
}

bastion_user() {
  printf '%s' "${SERVER_USERS[$BASTION_INDEX]}"
}

bastion_key() {
  printf '%s' "${SERVER_KEYS[$BASTION_INDEX]}"
}

bastion_run() {
  ssh $(ssh_opts_direct "$(bastion_key)") "$(bastion_user)@${SERVER_IPS[$BASTION_INDEX]}" "$@"
}

remote_key_name_for_index() {
  local i="$1"
  basename "${SERVER_KEYS[$i]}"
}

remote_ssh_prefix_for_index() {
  local i="$1"
  printf 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/tyche_known_hosts -o ConnectTimeout=%q -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -i ~/%s/%s %s@%s' \
    "$SSH_CONNECT_TIMEOUT" "$REMOTE_PEM_DIR" "$(remote_key_name_for_index "$i")" "${SERVER_USERS[$i]}" "${SERVER_IPS[$i]}"
}

remote_run() {
	local i="$1" cmd="$2"
	if [[ "$i" -eq "$BASTION_INDEX" ]]; then
		bastion_run "$cmd"
	elif [[ "$RUN_COMMANDS_VIA_BASTION" == "1" ]]; then
		local quoted
		printf -v quoted '%q' "$cmd"
		bastion_run "$(remote_ssh_prefix_for_index "$i") $quoted"
	else
		ssh $(ssh_opts_direct "${SERVER_KEYS[$i]}") "${SERVER_USERS[$i]}@${SERVER_IPS[$i]}" "$cmd"
	fi
}

detect_user_direct() {
  local i="$1" user
  if [[ -n "${SERVER_USERS[$i]}" ]]; then
    user="${SERVER_USERS[$i]}"
    if ssh $(ssh_opts_direct "${SERVER_KEYS[$i]}") "$user@${SERVER_IPS[$i]}" 'hostname >/dev/null' >/dev/null 2>&1; then
      return 0
    fi
  fi
  for user in "$SSH_USER" ubuntu ec2-user admin; do
    [[ -n "$user" ]] || continue
    if ssh $(ssh_opts_direct "${SERVER_KEYS[$i]}") "$user@${SERVER_IPS[$i]}" 'hostname >/dev/null' >/dev/null 2>&1; then
      SERVER_USERS[$i]="$user"
      return 0
    fi
  done
  return 1
}

wait_detect_user_direct() {
  local i="$1" tries="${2:-36}" n
  for n in $(seq 1 "$tries"); do
    if detect_user_direct "$i"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

filter_servers_reachable_from_bastion() {
	local keep_regions=() keep_ips=() keep_keys=() keep_users=() keep_instance_ids=()
	local i
	keep_regions+=("${SERVER_REGIONS[$BASTION_INDEX]}")
	keep_ips+=("${SERVER_IPS[$BASTION_INDEX]}")
	keep_keys+=("${SERVER_KEYS[$BASTION_INDEX]}")
	keep_users+=("${SERVER_USERS[$BASTION_INDEX]}")
	keep_instance_ids+=("${SERVER_INSTANCE_IDS[$BASTION_INDEX]}")

	for i in "${!SERVER_IPS[@]}"; do
		[[ "$i" -eq "$BASTION_INDEX" ]] && continue
		[[ "${#keep_ips[@]}" -ge "$M" ]] && break
		SERVER_USERS[$i]="${SERVER_USERS[$i]:-$SSH_USER}"
		if [[ -z "${SERVER_USERS[$i]}" ]]; then
			SERVER_USERS[$i]=ubuntu
		fi
		if bastion_run "ping -c 1 -W 2 ${SERVER_IPS[$i]} >/dev/null" >/dev/null 2>&1; then
			keep_regions+=("${SERVER_REGIONS[$i]}")
			keep_ips+=("${SERVER_IPS[$i]}")
			keep_keys+=("${SERVER_KEYS[$i]}")
			keep_users+=("${SERVER_USERS[$i]}")
			keep_instance_ids+=("${SERVER_INSTANCE_IDS[$i]}")
    else
      log "skipping unreachable server from bastion ip=${SERVER_IPS[$i]} key=${SERVER_KEYS[$i]}"
    fi
  done

  SERVER_REGIONS=("${keep_regions[@]}")
  SERVER_IPS=("${keep_ips[@]}")
  SERVER_KEYS=("${keep_keys[@]}")
  SERVER_USERS=("${keep_users[@]}")
  SERVER_INSTANCE_IDS=("${keep_instance_ids[@]}")
  BASTION_INDEX=0
}

detect_user_via_bastion() {
  local i="$1" user prefix
  for user in "${SERVER_USERS[$i]}" "$SSH_USER" ubuntu ec2-user admin; do
    [[ -n "$user" ]] || continue
    SERVER_USERS[$i]="$user"
    prefix="$(remote_ssh_prefix_for_index "$i")"
    if bastion_run "$prefix 'hostname >/dev/null'" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

sync_pems_to_bastion() {
  log "syncing local pems to bastion ${SERVER_IPS[$BASTION_INDEX]}"
  bastion_run "mkdir -p ~/$REMOTE_PEM_DIR && chmod 700 ~/$REMOTE_PEM_DIR"
  rsync -az --delete \
    -e "ssh $(ssh_opts_direct "$(bastion_key)")" \
    "$PEM_DIR/" "$(bastion_user)@${SERVER_IPS[$BASTION_INDEX]}:~/$REMOTE_PEM_DIR/"
  bastion_run "chmod 600 ~/$REMOTE_PEM_DIR/*.pem 2>/dev/null || true"
}

check_bastion_reaches_all() {
	local i
	for i in $(seq 0 $((M - 1))); do
		if [[ "$i" -eq "$BASTION_INDEX" ]]; then
			continue
		fi
		log "checking bastion -> host$i ${SERVER_IPS[$i]} by ping"
		bastion_run "ping -c 1 -W 2 ${SERVER_IPS[$i]} >/dev/null"
	done
}

install_remote_tools() {
  local i="$1"
  remote_run "$i" 'if ! command -v /usr/bin/time >/dev/null 2>&1; then if command -v apt-get >/dev/null 2>&1; then sudo apt-get update -y && sudo apt-get install -y time rsync curl; elif command -v yum >/dev/null 2>&1; then sudo yum install -y time rsync curl; fi; fi'
}

install_go_on_bastion() {
  if bastion_run 'command -v go >/dev/null 2>&1 || command -v /usr/local/go/bin/go >/dev/null 2>&1'; then
    return 0
  fi
  log "installing Go on bastion"
  bastion_run 'set -e; curl -fsSL https://go.dev/dl/go1.25.4.linux-amd64.tar.gz -o /tmp/go.tar.gz; sudo rm -rf /usr/local/go; sudo tar -C /usr/local -xzf /tmp/go.tar.gz; grep -q /usr/local/go/bin ~/.profile 2>/dev/null || echo "export PATH=/usr/local/go/bin:$PATH" >> ~/.profile'
}

prepare_servers() {
  local i
  discover_servers_from_pems
  if ! choose_bastion; then
    log "no local-pingable bastion from pems; querying AWS running instances"
    discover_running_aws_servers
    choose_bastion || true
  fi
  if [[ "$BASTION_INDEX" -lt 0 ]]; then
    log "no local-pingable running bastion found; starting stopped instances before creating one"
    start_stopped_aws_servers
    choose_bastion || true
  fi
  if [[ "$BASTION_INDEX" -lt 0 ]]; then
    log "no local-pingable bastion found; creating one in ${REGIONS_LIST[0]}"
    launch_server "${REGIONS_LIST[0]}"
    choose_bastion || die "created a server, but it is not reachable by local ping; check ICMP/security-group rules"
  fi
  ensure_enough_servers
  if [[ "$BASTION_INDEX" -ne 0 ]]; then
    swap_server_indexes 0 "$BASTION_INDEX"
    BASTION_INDEX=0
  fi

  for i in $(seq 0 $((M - 1))); do
    if [[ "$i" -eq "$BASTION_INDEX" ]]; then
      wait_detect_user_direct "$i" || die "cannot ssh to bastion ${SERVER_IPS[$i]}"
    fi
  done
  log "bastion selected host$BASTION_INDEX region=${SERVER_REGIONS[$BASTION_INDEX]} ip=${SERVER_IPS[$BASTION_INDEX]} user=${SERVER_USERS[$BASTION_INDEX]}"
  sync_pems_to_bastion
  filter_servers_reachable_from_bastion
  ensure_enough_servers
  sync_pems_to_bastion

	check_bastion_reaches_all

  local pids=()
  for i in $(seq 0 $((M - 1))); do
    install_remote_tools "$i" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" || die "failed to install remote tools"
  install_go_on_bastion
}

node_host() {
  local node="$1"
  printf '%d' "$((node % M))"
}

seed_for_node() {
  local node="$1"
  printf 'tyche-node-%04d' "$node" | shasum -a 256 | awk '{print $1}'
}

generate_json_config() {
  local proto="$1" protocol="$2" file="$3"
  local node host port comma f
  f="$(protocol_f "$proto")"
  {
    printf '{\n'
    printf '  "name": "aws-m%dn%d",\n' "$M" "$N"
    printf '  "protocol": "%s",\n' "$protocol"
    printf '  "transport": "tcp",\n'
    printf '  "f": %d,\n' "$f"
    printf '  "round": %d,\n' "$EPOCHS"
    printf '  "queue_len": %d,\n' "$QUEUE_LEN"
    printf '  "listen_ip": "0.0.0.0",\n'
    printf '  "producer_interval_ms": %d,\n' "$PRODUCER_MS"
    printf '  "prefill_ms": %d,\n' "$PREFILL_MS"
    printf '  "epoch_timeout_ms": %d,\n' "$EPOCH_TIMEOUT_MS"
    printf '  "report_interval_ms": %d,\n' "$REPORT_MS"
    printf '  "linger_ms": %d,\n' "$LINGER_MS"
    printf '  "batch_size": 1,\n'
    printf '  "max_pool": 16,\n'
    printf '  "log_level": 1,\n'
    printf '  "seed": "%s",\n' "$(printf '%s-%s-%s' "$proto" "$M" "$N" | shasum -a 256 | awk '{print $1}')"
    printf '  "cluster_index": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": %d%s\n' "$node" "$node" "$comma"
    done
    printf '  },\n'
    printf '  "peers": [\n'
    for node in $(seq 0 $((N - 1))); do
      host="$(node_host "$node")"
      port=$((BASE_PORT + node))
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    {"id": "node%d", "addr": "%s:%d"}%s\n' "$node" "${SERVER_IPS[$host]}" "$port" "$comma"
    done
    printf '  ],\n'
    printf '  "node_key_seed": {\n'
    for node in $(seq 0 $((N - 1))); do
      comma=','
      [[ "$node" -eq $((N - 1)) ]] && comma=''
      printf '    "node%d": "%s"%s\n' "$node" "$(seed_for_node "$node")" "$comma"
    done
    printf '  }\n'
    printf '}\n'
  } > "$file"
}

generate_configs() {
  mkdir -p "$GEN_DIR"
  local node host port comma
  : > "$GEN_DIR/tyche_peers.txt"
  for node in $(seq 0 $((N - 1))); do
    host="$(node_host "$node")"
    port=$((BASE_PORT + node))
    comma=','
    [[ "$node" -eq $((N - 1)) ]] && comma=''
    printf 'node%d=%s:%d%s' "$node" "${SERVER_IPS[$host]}" "$port" "$comma" >> "$GEN_DIR/tyche_peers.txt"
  done
  generate_json_config asyrand asyrand-v1 "$GEN_DIR/asyrand.json"
  generate_json_config grandline grandline "$GEN_DIR/grandline.json"
  generate_json_config spurt spurt-v1 "$GEN_DIR/spurt.json"
}

protocol_f() {
  local proto="$1"
  case "$proto" in
    grandline)
      printf '%d' "$GRANDLINE_F"
      ;;
    tyche|asyrand|spurt)
      printf '%d' "$BFT_F"
      ;;
    *)
      die "unknown protocol: $proto"
      ;;
  esac
}

validate_protocol_params() {
  local proto f
  for proto in "${PROTOCOLS_LIST[@]}"; do
    f="$(protocol_f "$proto")"
    case "$proto" in
      grandline)
        (( 2 * f + 1 <= N )) || die "invalid Grandline f=$f for N=$N; need 2f+1 <= N"
        ;;
      tyche|asyrand|spurt)
        (( 3 * f + 1 <= N )) || die "invalid $proto f=$f for N=$N; need 3f+1 <= N"
        ;;
      *)
        die "unknown protocol: $proto"
        ;;
    esac
  done
}

upload_source_to_bastion() {
	log "uploading local source to bastion"
	bastion_run "rm -rf ~/$REMOTE_DIR/AsyRand && mkdir -p ~/$REMOTE_DIR"
	rsync -az --delete \
		--exclude '.git' \
		--exclude 'pems' \
    --exclude 'benchmarks/aws_*' \
    -e "ssh $(ssh_opts_direct "$(bastion_key)")" \
    "$REPO_ROOT/" "$(bastion_user)@${SERVER_IPS[$BASTION_INDEX]}:~/$REMOTE_DIR/"
}

build_on_bastion() {
	log "building binaries on bastion"
	bastion_run "set -e; export PATH=/usr/local/go/bin:\$PATH; cd ~/$REMOTE_DIR; test -d asyrand || { echo 'missing lowercase asyrand directory' >&2; exit 1; }; mkdir -p bin; (cd Tyche && go build -o ../bin/tyche ./cmd/tyche); (cd asyrand && go build -o ../bin/asyrand ./cmd/asyrand); (cd grandline && go build -o ../bin/grandline ./cmd/grandline); (cd spurt && go build -o ../bin/spurt ./cmd/spurt)"
}

distribute_runtime_from_bastion() {
  local i pids=()
  log "distributing binaries/configs from bastion to workers"
  for i in $(seq 0 $((M - 1))); do
    [[ "$i" -eq "$BASTION_INDEX" ]] && continue
    bastion_run "$(remote_ssh_prefix_for_index "$i") 'mkdir -p ~/$REMOTE_DIR/bin ~/$REMOTE_DIR/benchmarks/generated_aws_m${M}n${N}'" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" || die "failed to prepare worker runtime directories"
  pids=()
  for i in $(seq 0 $((M - 1))); do
    [[ "$i" -eq "$BASTION_INDEX" ]] && continue
    bastion_run "rsync -az --delete -e 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/tyche_known_hosts -o ConnectTimeout=$SSH_CONNECT_TIMEOUT -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -i ~/$REMOTE_PEM_DIR/$(remote_key_name_for_index "$i")' ~/$REMOTE_DIR/bin/ ${SERVER_USERS[$i]}@${SERVER_IPS[$i]}:~/$REMOTE_DIR/bin/ && rsync -az --delete -e 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/tyche_known_hosts -o ConnectTimeout=$SSH_CONNECT_TIMEOUT -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -i ~/$REMOTE_PEM_DIR/$(remote_key_name_for_index "$i")' ~/$REMOTE_DIR/benchmarks/generated_aws_m${M}n${N}/ ${SERVER_USERS[$i]}@${SERVER_IPS[$i]}:~/$REMOTE_DIR/benchmarks/generated_aws_m${M}n${N}/" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" || die "failed to distribute runtime"
}

deploy_and_build() {
  generate_configs
  upload_source_to_bastion
  build_on_bastion
  distribute_runtime_from_bastion
}

stop_remote_processes() {
  local i pids=()
  for i in $(seq 0 $((M - 1))); do
    remote_run "$i" "pkill -f '$REMOTE_DIR/bin/(tyche|asyrand|grandline|spurt)' >/dev/null 2>&1 || true" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" >/dev/null 2>&1 || true
}

remote_command_for_node() {
  local proto="$1" node="$2" log_file="$3"
  local port=$((BASE_PORT + node))
  case "$proto" in
    tyche)
      local peers
      peers="$(< "$GEN_DIR/tyche_peers.txt")"
      printf 'cd ~/%q && mkdir -p %q && export PATH=/usr/local/go/bin:$PATH GOMAXPROCS=%q && /usr/bin/time -v ./bin/tyche -transport tcp -node node%d -n %d -f %d -epochs %d -peers %q -listen 0.0.0.0:%d -producer-ms %d -prefill-ms %d -epoch-timeout-ms %d -report-ms %d > %q 2>&1' \
        "$REMOTE_DIR" "$(dirname "$log_file")" "$GOMAXPROCS_REMOTE" "$node" "$N" "$BFT_F" "$EPOCHS" "$peers" "$port" "$PRODUCER_MS" "$PREFILL_MS" "$EPOCH_TIMEOUT_MS" "$REPORT_MS" "$log_file"
      ;;
    asyrand|grandline|spurt)
      printf 'cd ~/%q && mkdir -p %q && export PATH=/usr/local/go/bin:$PATH GOMAXPROCS=%q && /usr/bin/time -v ./bin/%s -config benchmarks/generated_aws_m%dn%d/%s.json -transport tcp -node node%d > %q 2>&1' \
        "$REMOTE_DIR" "$(dirname "$log_file")" "$GOMAXPROCS_REMOTE" "$proto" "$M" "$N" "$proto" "$node" "$log_file"
      ;;
    *)
      die "unknown protocol: $proto"
      ;;
  esac
}

fetch_log_from_remote() {
	local host="$1" remote_log="$2" local_log="$3" tmp
	tmp="/tmp/tyche_fetch_$(basename "$local_log")"
	if [[ "$host" -eq "$BASTION_INDEX" ]]; then
		scp $(ssh_opts_direct "$(bastion_key)") "$(bastion_user)@${SERVER_IPS[$BASTION_INDEX]}:~/$REMOTE_DIR/$remote_log" "$local_log" >/dev/null
	elif [[ "$RUN_COMMANDS_VIA_BASTION" == "1" ]]; then
		bastion_run "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/tyche_known_hosts -o ConnectTimeout=$SSH_CONNECT_TIMEOUT -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -i ~/$REMOTE_PEM_DIR/$(remote_key_name_for_index "$host") ${SERVER_USERS[$host]}@${SERVER_IPS[$host]}:~/$REMOTE_DIR/$remote_log $tmp"
		scp $(ssh_opts_direct "$(bastion_key)") "$(bastion_user)@${SERVER_IPS[$BASTION_INDEX]}:$tmp" "$local_log" >/dev/null
		bastion_run "rm -f $tmp"
	else
		scp $(ssh_opts_direct "${SERVER_KEYS[$host]}") "${SERVER_USERS[$host]}@${SERVER_IPS[$host]}:~/$REMOTE_DIR/$remote_log" "$local_log" >/dev/null
	fi
}

remote_command_for_host() {
  local proto="$1" host="$2" node remote_log cmd host_cmd
  host_cmd='set -u; pids=""; failed=0;'
  for node in $(seq 0 $((N - 1))); do
    [[ "$(node_host "$node")" -eq "$host" ]] || continue
    remote_log="runlogs/$proto/node${node}.log"
    cmd="$(remote_command_for_node "$proto" "$node" "$remote_log")"
    host_cmd+=" ( $cmd ) & pids=\"\$pids \$!\";"
  done
  host_cmd+=' for p in $pids; do wait "$p" || failed=1; done; exit "$failed"'
  printf '%s' "$host_cmd"
}

run_protocol() {
  local proto="$1" run_dir="$OUT_ROOT/$proto" node host remote_log cmd pid failed=0
  mkdir -p "$run_dir"
  log "running $proto on M=$M servers, N=$N nodes, epochs=$EPOCHS"
  stop_remote_processes
  local pids=()
  for host in $(seq 0 $((M - 1))); do
    remote_run "$host" "mkdir -p ~/$REMOTE_DIR/runlogs/$proto && rm -f ~/$REMOTE_DIR/runlogs/$proto/*.log" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" || die "failed to prepare remote logs for $proto"

  pids=()
  for host in $(seq 0 $((M - 1))); do
    cmd="$(remote_command_for_host "$proto" "$host")"
    remote_run "$host" "$cmd" &
    pids+=("$!")
  done
  local startup_wait
  startup_wait="$(startup_wait_seconds)"
  if [[ "$startup_wait" -gt 0 ]]; then
    log "waiting ${startup_wait}s for $proto startup and p2p connections"
    sleep "$startup_wait"
  fi
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done

  pids=()
  for node in $(seq 0 $((N - 1))); do
    host="$(node_host "$node")"
    remote_log="runlogs/$proto/node${node}.log"
    fetch_log_from_remote "$host" "$remote_log" "$run_dir/node${node}.log" &
    pids+=("$!")
  done
  wait_all "${pids[@]}" || failed=1
  if [[ "$failed" -ne 0 ]]; then
    tail -n 80 "$run_dir"/node*.log >&2 || true
    die "$proto run failed"
  fi
}

parse_duration_seconds() {
  local raw="$1"
  awk -v s="$raw" 'BEGIN {
    n=split(s,a,":");
    if (n==3) print a[1]*3600+a[2]*60+a[3];
    else if (n==2) print a[1]*60+a[2];
    else print s+0;
  }'
}

parse_results() {
  local csv="$OUT_ROOT/results.csv" proto node host logf final thr bw sent recv elapsed user sys elapsed_s cpu_pct
  printf 'protocol,node,host,region,ip,throughput_beacon_min,throughput_beacon_s,latency_s,bandwidth_kbps,sent_kb,recv_kb,cpu_percent,log\n' > "$csv"
  for proto in "${PROTOCOLS_LIST[@]}"; do
    for node in $(seq 0 $((N - 1))); do
      host="$(node_host "$node")"
      logf="$OUT_ROOT/$proto/node${node}.log"
      final="$(grep 'final metrics' "$logf" | tail -n 1 || true)"
      [[ -n "$final" ]] || die "missing final metrics: $logf"
      thr="$(grep -o 'throughput=[0-9.]*' <<< "$final" | cut -d= -f2)"
      bw="$(grep -o 'bandwidth=[0-9.]*' <<< "$final" | cut -d= -f2)"
      sent="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^sent=[0-9.]+KB$/) {sub(/^sent=/,"",$i); sub(/KB$/,"",$i); print $i; exit}}' <<< "$final")"
      recv="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^recv=[0-9.]+KB$/) {sub(/^recv=/,"",$i); sub(/KB$/,"",$i); print $i; exit}}' <<< "$final")"
      elapsed="$(grep 'Elapsed (wall clock) time' "$logf" | tail -n 1 | awk -F': ' '{print $2}')"
      user="$(grep 'User time (seconds)' "$logf" | tail -n 1 | awk -F': ' '{print $2}')"
      sys="$(grep 'System time (seconds)' "$logf" | tail -n 1 | awk -F': ' '{print $2}')"
      elapsed_s="$(parse_duration_seconds "$elapsed")"
      cpu_pct="$(awk -v u="$user" -v s="$sys" -v e="$elapsed_s" 'BEGIN { if (e<=0) e=1; printf "%.2f", (u+s)/e*100 }')"
      printf '%s,node%d,host%d,%s,%s,%s,%.4f,%.4f,%s,%s,%s,%s,%s\n' \
        "$proto" "$node" "$host" "${SERVER_REGIONS[$host]}" "${SERVER_IPS[$host]}" "$thr" \
        "$(awk -v t="$thr" 'BEGIN {printf "%.4f", t/60}')" \
        "$(awk -v t="$thr" 'BEGIN {if (t<=0) printf "0"; else printf "%.4f", 60/t}')" \
        "$bw" "$sent" "$recv" "$cpu_pct" "$logf" >> "$csv"
    done
  done
}

generate_comparison_svg() {
  local csv="$OUT_ROOT/results.csv" svg="$OUT_ROOT/protocol_comparison.svg"
  awk -F, -v svg="$svg" '
    NR > 1 {
      p=$1
      thr[p]+=$7
      lat[p]+=$8
      bw[p]+=$9
      cpu[p]+=$12
      n[p]++
    }
    END {
      split("tyche asyrand grandline spurt", order, " ")
      for (i=1; i<=4; i++) {
        p=order[i]
        if (n[p] == 0) continue
        thr[p]/=n[p]
        lat[p]/=n[p]
        bw[p]/=n[p]
        cpu[p]/=n[p]
        if (thr[p] > maxThr) maxThr=thr[p]
        if (lat[p] > maxLat) maxLat=lat[p]
        if (bw[p] > maxBw) maxBw=bw[p]
        if (cpu[p] > maxCpu) maxCpu=cpu[p]
      }
      print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1180\" height=\"760\" viewBox=\"0 0 1180 760\">" > svg
      print "<rect width=\"1180\" height=\"760\" fill=\"#ffffff\"/>" >> svg
      print "<text x=\"40\" y=\"45\" font-family=\"Arial\" font-size=\"24\" font-weight=\"700\">AWS Beacon Protocol Comparison</text>" >> svg
      draw("Throughput (beacon/s)", 40, 85, maxThr, "thr")
      draw("Latency (s/beacon)", 610, 85, maxLat, "lat")
      draw("Bandwidth (KB/s)", 40, 415, maxBw, "bw")
      draw("CPU (%)", 610, 415, maxCpu, "cpu")
      print "</svg>" >> svg
    }
    function metric(kind,p) {
      if (kind == "thr") return thr[p]
      if (kind == "lat") return lat[p]
      if (kind == "bw") return bw[p]
      return cpu[p]
    }
    function draw(title,x,y,maxv,kind, i,p,v,bar,h) {
      if (maxv <= 0) maxv=1
      print "<text x=\"" x "\" y=\"" y "\" font-family=\"Arial\" font-size=\"18\" font-weight=\"700\">" title "</text>" >> svg
      print "<line x1=\"" x "\" y1=\"" y+250 "\" x2=\"" x+500 "\" y2=\"" y+250 "\" stroke=\"#333\"/>" >> svg
      for (i=1; i<=4; i++) {
        p=order[i]
        v=metric(kind,p)
        h=v/maxv*205
        bar=x+40+(i-1)*115
        printf "<rect x=\"%d\" y=\"%.2f\" width=\"64\" height=\"%.2f\" fill=\"#2563eb\"/>\n", bar, y+250-h, h >> svg
        printf "<text x=\"%d\" y=\"%.2f\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"13\">%.2f</text>\n", bar+32, y+238-h, v >> svg
        print "<text x=\"" bar+32 "\" y=\"" y+275 "\" text-anchor=\"middle\" font-family=\"Arial\" font-size=\"13\">" p "</text>" >> svg
      }
    }
  ' "$csv"
}

write_state() {
  local state="$OUT_ROOT/aws_state.env" i
  mkdir -p "$OUT_ROOT"
  {
    printf 'RUN_NAME=%q\nM=%q\nN=%q\nEPOCHS=%q\nBFT_F=%q\nGRANDLINE_F=%q\n' "$RUN_NAME" "$M" "$N" "$EPOCHS" "$BFT_F" "$GRANDLINE_F"
    printf 'BASTION_INDEX=%q\nBASTION_IP=%q\n' "$BASTION_INDEX" "${SERVER_IPS[$BASTION_INDEX]}"
    for i in $(seq 0 $((M - 1))); do
      printf 'SERVER_%d_REGION=%q\n' "$i" "${SERVER_REGIONS[$i]}"
      printf 'SERVER_%d_IP=%q\n' "$i" "${SERVER_IPS[$i]}"
      printf 'SERVER_%d_USER=%q\n' "$i" "${SERVER_USERS[$i]}"
      printf 'SERVER_%d_KEY=%q\n' "$i" "${SERVER_KEYS[$i]}"
      printf 'SERVER_%d_INSTANCE_ID=%q\n' "$i" "${SERVER_INSTANCE_IDS[$i]}"
    done
  } > "$state"
}

main() {
  [[ "$M" =~ ^[0-9]+$ && "$M" -gt 0 ]] || die "M must be a positive integer"
  [[ "$N" =~ ^[0-9]+$ && "$N" -gt 0 ]] || die "N must be a positive integer"
  need_cmd aws
  need_cmd ssh
  need_cmd scp
  need_cmd rsync
  need_cmd ping
  need_cmd shasum
  split_csv "$REGIONS_CSV" REGIONS_LIST
  split_csv "$PROTOCOLS_CSV" PROTOCOLS_LIST
  validate_protocol_params
  (( ${#REGIONS_LIST[@]} <= 16 )) || REGIONS_LIST=("${REGIONS_LIST[@]:0:16}")
  mkdir -p "$OUT_ROOT" "$GEN_DIR" "$PEM_DIR"

  prepare_servers
  write_state
  deploy_and_build
  for proto in "${PROTOCOLS_LIST[@]}"; do
    run_protocol "$proto"
  done
  parse_results
  generate_comparison_svg
  stop_remote_processes
  log "done"
  log "results: $OUT_ROOT/results.csv"
  log "figure:  $OUT_ROOT/protocol_comparison.svg"
  log "logs:    $OUT_ROOT"
  log "state:   $OUT_ROOT/aws_state.env"
}

main "$@"
