import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .paths import REPO_ROOT
from .errors import BenchError


try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import BotoCoreError
    from botocore.exceptions import ClientError
    from botocore.exceptions import ProxyConnectionError
    from botocore.parsers import ResponseParserError
except ImportError:  # pragma: no cover - exercised only when dependencies are missing.
    boto3 = None
    BotoConfig = None
    BotoCoreError = Exception
    ClientError = Exception
    ProxyConnectionError = Exception
    ResponseParserError = Exception


INSTANCE_NAME = "tyche-beacon-node"
SECURITY_GROUP_NAME = "tyche-beacon-bench"
PROJECT_TAG = "Tyche"


@dataclass(frozen=True)
class AwsSettings:
    regions: list[str]
    instance_type: str
    key_name: str
    key_path: Path
    p2p_port: int
    volume_gb: int


def _settings_path(path=None):
    return Path(path).resolve() if path else (REPO_ROOT / "benchmark" / "settings.json")


def load_settings(path=None):
    settings_file = _settings_path(path)
    if not settings_file.exists():
        raise BenchError(f"AWS settings file does not exist: {settings_file}")
    try:
        raw = json.loads(settings_file.read_text(encoding="utf-8"))
        key_path = Path(raw["key"]["path"])
        if not key_path.is_absolute():
            key_path = (settings_file.parent / key_path).resolve()
        regions = raw["instances"]["regions"]
        regions = regions if isinstance(regions, list) else [regions]
        return AwsSettings(
            regions=[str(region) for region in regions],
            instance_type=str(raw["instances"].get("type", "c6i.xlarge")),
            key_name=str(raw["key"]["name"]),
            key_path=key_path,
            p2p_port=int(raw.get("port", {}).get("p2p", 9000)),
            volume_gb=int(raw["instances"].get("volume_gb", 24)),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BenchError(f"invalid AWS settings file {settings_file}: {exc}") from exc


def _require_boto3():
    if boto3 is None:
        raise BenchError("boto3 is required. Run: .\\.venv\\Scripts\\python -m pip install -r requirements.txt")


def _client(region):
    _require_boto3()
    if os.environ.get("AWS_USE_PROXY", "").lower() in {"1", "true", "yes"}:
        return boto3.client("ec2", region_name=region)
    return boto3.client("ec2", region_name=region, config=BotoConfig(proxies={}))


def _aws_error(exc):
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'AWS')} {error.get('Message', exc)}"
    if isinstance(exc, ProxyConnectionError):
        return (
            f"{exc}; boto3 is using proxy environment variables. "
            "This benchmark disables proxies for AWS by default; if you explicitly need the proxy, run `$env:AWS_USE_PROXY='1'`."
        )
    return str(exc)


def _describe_error(action, region, exc):
    raise BenchError(f"failed to {action} in {region}: {_aws_error(exc)}") from exc


def _instance_filters(states=None):
    filters = [
        {"Name": "tag:Name", "Values": [INSTANCE_NAME]},
        {"Name": "tag:Project", "Values": [PROJECT_TAG]},
    ]
    if states:
        filters.append({"Name": "instance-state-name", "Values": states})
    return filters


def _instances(region, states=None):
    try:
        response = _client(region).describe_instances(Filters=_instance_filters(states))
    except (ClientError, BotoCoreError, ResponseParserError) as exc:
        _describe_error("describe instances", region, exc)
    out = []
    for reservation in response.get("Reservations", []):
        out.extend(reservation.get("Instances", []))
    return out


def _default_vpc(client):
    response = client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpcs = response.get("Vpcs", [])
    if not vpcs:
        raise BenchError(f"no default VPC in region {client.meta.region_name}")
    return vpcs[0]["VpcId"]


def _supported_availability_zones(client, instance_type):
    response = client.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )
    return {
        offering["Location"]
        for offering in response.get("InstanceTypeOfferings", [])
        if offering.get("Location")
    }


def _default_subnets(client, instance_type=None):
    response = client.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])
    subnets = sorted(response.get("Subnets", []), key=lambda subnet: subnet.get("AvailabilityZone", ""))
    if not subnets:
        raise BenchError(f"no default subnet in region {client.meta.region_name}")
    if instance_type:
        supported_zones = _supported_availability_zones(client, instance_type)
        supported_subnets = [
            subnet for subnet in subnets if subnet.get("AvailabilityZone") in supported_zones
        ]
        if supported_subnets:
            return supported_subnets
        zones = ", ".join(sorted(supported_zones)) or "none"
        raise BenchError(
            f"no default subnet in {client.meta.region_name} supports {instance_type}; "
            f"supported availability zones: {zones}"
        )
    return subnets


def _default_subnet(client, instance_type=None):
    return _default_subnets(client, instance_type)[0]["SubnetId"]


def _ensure_security_group(region, settings):
    client = _client(region)
    try:
        response = client.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP_NAME]}]
        )
        groups = response.get("SecurityGroups", [])
        if groups:
            sg_id = groups[0]["GroupId"]
        else:
            sg_id = client.create_security_group(
                GroupName=SECURITY_GROUP_NAME,
                Description="Tyche beacon benchmark",
                VpcId=_default_vpc(client),
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": "Name", "Value": SECURITY_GROUP_NAME},
                            {"Key": "Project", "Value": PROJECT_TAG},
                        ],
                    }
                ],
            )["GroupId"]

        permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "ssh"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": settings.p2p_port,
                "ToPort": settings.p2p_port + 4096,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "beacon-peers"}],
            },
            {
                "IpProtocol": "icmp",
                "FromPort": 8,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "ping"}],
            },
        ]
        try:
            client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permissions)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidPermission.Duplicate":
                raise
        return sg_id
    except (ClientError, BotoCoreError, ResponseParserError) as exc:
        raise BenchError(f"failed to ensure security group in {region}: {_aws_error(exc)}") from exc


def _latest_ubuntu_ami(region):
    client = _client(region)
    try:
        response = client.describe_images(
            Owners=["099720109477"],
            Filters=[
                {
                    "Name": "name",
                    "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"],
                },
                {"Name": "state", "Values": ["available"]},
            ],
        )
        images = sorted(response.get("Images", []), key=lambda item: item["CreationDate"], reverse=True)
        if not images:
            raise BenchError(f"no Ubuntu 22.04 AMI found in region {region}")
        return images[0]["ImageId"]
    except (ClientError, BotoCoreError, ResponseParserError) as exc:
        raise BenchError(f"failed to find Ubuntu AMI in {region}: {_aws_error(exc)}") from exc


def _ensure_key_pair(region, settings):
    if not settings.key_path.exists():
        raise BenchError(f"local SSH key does not exist: {settings.key_path}")
    try:
        _client(region).describe_key_pairs(KeyNames=[settings.key_name])
    except (ClientError, BotoCoreError, ResponseParserError) as exc:
        if not isinstance(exc, ClientError):
            raise BenchError(
                f"AWS key pair {settings.key_name!r} is not available in {region}: {_aws_error(exc)}"
            ) from exc
        code = exc.response.get("Error", {}).get("Code")
        if code != "InvalidKeyPair.NotFound":
            raise BenchError(
                f"AWS key pair {settings.key_name!r} is not available in {region}: {_aws_error(exc)}"
            ) from exc
        public_key = _public_key_material(settings.key_path)
        try:
            _client(region).import_key_pair(
                KeyName=settings.key_name,
                PublicKeyMaterial=public_key,
                TagSpecifications=[
                    {
                        "ResourceType": "key-pair",
                        "Tags": [
                            {"Key": "Name", "Value": settings.key_name},
                            {"Key": "Project", "Value": PROJECT_TAG},
                        ],
                    }
                ],
            )
            print(f"{region}: imported key pair {settings.key_name} from {settings.key_path}")
        except (ClientError, BotoCoreError, ResponseParserError) as import_exc:
            raise BenchError(
                f"failed to import AWS key pair {settings.key_name!r} in {region}: {_aws_error(import_exc)}"
            ) from import_exc


def _public_key_material(key_path):
    pub_path = key_path.with_name(key_path.name + ".pub")
    if pub_path.exists():
        return pub_path.read_text(encoding="utf-8").strip()
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        public_key = result.stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BenchError(
            f"failed to derive public key from {key_path}; create {pub_path} or install ssh-keygen"
        ) from exc
    if not public_key:
        raise BenchError(f"ssh-keygen returned an empty public key for {key_path}")
    return public_key


def _is_retryable_launch_error(exc):
    if not isinstance(exc, ClientError):
        return False
    code = exc.response.get("Error", {}).get("Code")
    return code in {
        "InsufficientInstanceCapacity",
        "Unsupported",
        "UnsupportedOperation",
    }


def _launch_instances(client, region, settings, nodes, sg_id):
    last_exc = None
    attempted = []
    for subnet in _default_subnets(client, settings.instance_type):
        subnet_id = subnet["SubnetId"]
        zone = subnet.get("AvailabilityZone", subnet_id)
        attempted.append(zone)
        try:
            response = client.run_instances(
                ImageId=_latest_ubuntu_ami(region),
                InstanceType=settings.instance_type,
                KeyName=settings.key_name,
                MinCount=nodes,
                MaxCount=nodes,
                SecurityGroupIds=[sg_id],
                SubnetId=subnet_id,
                BlockDeviceMappings=[
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {
                            "VolumeType": "gp3",
                            "VolumeSize": settings.volume_gb,
                            "DeleteOnTermination": True,
                        },
                    }
                ],
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": INSTANCE_NAME},
                            {"Key": "Project", "Value": PROJECT_TAG},
                            {"Key": "Role", "Value": "beacon-benchmark"},
                        ],
                    }
                ],
            )
            if len(attempted) > 1:
                print(f"{region}: launched in {zone} after trying {', '.join(attempted[:-1])}")
            return response
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            if not _is_retryable_launch_error(exc):
                raise
            last_exc = exc
            print(f"{region}: launch failed in {zone}: {_aws_error(exc)}; trying next AZ")

    zones = ", ".join(attempted) or "none"
    raise BenchError(
        f"failed to launch instances in {region}: tried availability zones {zones}; "
        f"last error: {_aws_error(last_exc)}"
    ) from last_exc


def create_instances(nodes=1, settings_file=None):
    settings = load_settings(settings_file)
    nodes = int(nodes)
    if nodes <= 0:
        raise BenchError("nodes must be positive")

    created = []
    print(f"Creating {nodes} instance(s) per region across {len(settings.regions)} region(s)")
    for region in settings.regions:
        client = _client(region)
        sg_id = _ensure_security_group(region, settings)
        _ensure_key_pair(region, settings)
        try:
            response = _launch_instances(client, region, settings, nodes, sg_id)
            ids = [instance["InstanceId"] for instance in response.get("Instances", [])]
            created.extend((region, instance_id) for instance_id in ids)
            print(f"{region}: launched {len(ids)} instance(s)")
        except BenchError:
            raise
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            raise BenchError(f"failed to launch instances in {region}: {_aws_error(exc)}") from exc

    by_region = {}
    for region, instance_id in created:
        by_region.setdefault(region, {"ids": []})["ids"].append(instance_id)

    for region, data in by_region.items():
        client = _client(region)
        ids = data["ids"]
        print(f"{region}: waiting for instance-running")
        client.get_waiter("instance_running").wait(InstanceIds=ids)
        print(f"{region}: waiting for status checks")
        client.get_waiter("instance_status_ok").wait(InstanceIds=ids)
        response = client.describe_instances(InstanceIds=ids)
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                ip = instance.get("PublicIpAddress")
                if ip:
                    print(f"{region}: {instance['InstanceId']} {ip} key={settings.key_path}")

    print("Create complete")


def _target_instance_ids(settings, states):
    out = {}
    for region in settings.regions:
        ids = [instance["InstanceId"] for instance in _instances(region, states)]
        if ids:
            out[region] = ids
    return out


def start_instances(max_per_region=10, settings_file=None):
    settings = load_settings(settings_file)
    total = 0
    for region, ids in _target_instance_ids(settings, ["stopped"]).items():
        ids = ids[: int(max_per_region)]
        if not ids:
            continue
        print(f"{region}: starting {len(ids)} instance(s)")
        try:
            _client(region).start_instances(InstanceIds=ids)
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            _describe_error("start instances", region, exc)
        total += len(ids)
    print(f"Started {total} instance(s)")


def stop_instances(settings_file=None):
    settings = load_settings(settings_file)
    total = 0
    for region, ids in _target_instance_ids(settings, ["pending", "running"]).items():
        print(f"{region}: stopping {len(ids)} instance(s)")
        try:
            _client(region).stop_instances(InstanceIds=ids)
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            _describe_error("stop instances", region, exc)
        total += len(ids)
    print(f"Stopping {total} instance(s)")


def destroy_instances(settings_file=None):
    settings = load_settings(settings_file)
    total = 0
    for region, ids in _target_instance_ids(settings, ["pending", "running", "stopping", "stopped"]).items():
        print(f"{region}: terminating {len(ids)} instance(s)")
        try:
            _client(region).terminate_instances(InstanceIds=ids)
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            _describe_error("terminate instances", region, exc)
        total += len(ids)
    print(f"Terminating {total} instance(s)")
    for region, ids in _target_instance_ids(settings, ["shutting-down"]).items():
        _client(region).get_waiter("instance_terminated").wait(InstanceIds=ids)
    print("Destroy complete")


def print_info(settings_file=None):
    settings = load_settings(settings_file)
    total = 0
    lines = []
    for region in settings.regions:
        region_instances = _instances(region, ["pending", "running", "stopping", "stopped"])
        if not region_instances:
            continue
        lines.append(f"\nRegion: {region.upper()}")
        for index, instance in enumerate(region_instances):
            state = instance.get("State", {}).get("Name", "unknown")
            ip = instance.get("PublicIpAddress", "")
            instance_id = instance.get("InstanceId", "")
            ssh = f"ssh -i {settings.key_path} ubuntu@{ip}" if ip else "(no public ip yet)"
            lines.append(f" {index}\t{state}\t{instance_id}\t{ssh}")
            total += 1
    print(
        "\n"
        "----------------------------------------------------------------\n"
        " INFO:\n"
        "----------------------------------------------------------------\n"
        f" Available machines: {total}\n"
        + "\n".join(lines)
        + "\n----------------------------------------------------------------\n"
    )
