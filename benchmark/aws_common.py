"""Shared AWS lifecycle and native execution; imports never contact AWS."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import time
import traceback

import docker_bench as measured
from bench_results import LOCK, REPO, SIZES, PROTOCOLS, utc, save, read, sha, read_csv, write_csv


def controller_files(driver_path, compact=False):
    """Every module required by a standalone frozen or remote controller."""
    driver = Path(driver_path).resolve()
    names = ['aws_common.py', 'bench_results.py', 'docker_bench.py']
    return [driver] + [driver.parent / name for name in names]


def dependency_hashes(driver_path, compact=False):
    return {p.name: sha(p) for p in controller_files(driver_path, compact)[1:]}


def stage_payload(root, driver_path, protocols, compact=False, scenario='single'):
    """Stage verified binaries, required Python dependencies and source provenance."""
    root = Path(root)
    frozen = REPO / 'benchmark/runs/frozen-final-20261026/runtime'
    source = read(frozen / 'source-manifest.json')
    mismatched = [name for name, want in source['files_sha256'].items()
                  if not (REPO / name).is_file() or sha(REPO / name) != want]
    assert not mismatched, 'current source differs from validated binaries; rebuild explicitly: ' + str(mismatched)
    expected = {name: source['binaries_sha256'][name] for name in protocols}
    payload = root / 'payload'
    (payload / 'bin').mkdir(parents=True)
    for name, want in expected.items():
        binary = frozen / 'bin' / name
        assert sha(binary) == want
        shutil.copy2(binary, payload / 'bin' / name)
        (payload / 'bin' / name).chmod(0o755)
    if compact:
        # The node collector runs independently of the AWS controller.
        for name in ('bench_results.py',):
            shutil.copy2(Path(driver_path).parent / name, payload / name)
    with tarfile.open(root / 'protocol.tar.gz', 'w:gz', compresslevel=1) as archive:
        for path in sorted(payload.rglob('*')):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(payload).as_posix(), recursive=False)
    with tarfile.open(root / 'source.tar.gz', 'w:gz') as archive:
        for name in source['files_sha256']:
            archive.add(REPO / name, arcname=name, recursive=False)
        for path in controller_files(driver_path, compact):
            archive.add(path, arcname='benchmark/' + path.name, recursive=False)
    return dict(scenario=scenario, source=source, deployed_binaries_sha256=expected,
                payload_sha256=sha(root / 'protocol.tar.gz'),
                source_archive_sha256=sha(root / 'source.tar.gz'),
                driver_sha256=sha(driver_path),
                dependencies_sha256=dependency_hashes(driver_path, compact),
                measurement_driver_sha256=sha(Path(driver_path).parent / 'docker_bench.py'))


def verify_controller(driver_path, root, scenario=None):
    manifest = read(Path(root) / 'payload-manifest.json')
    assert sha(driver_path) == manifest['driver_sha256'], 'run the frozen controller matching this manifest'
    expected = manifest['dependencies_sha256']
    assert expected == dependency_hashes(driver_path), 'shared controller dependency differs from frozen manifest'
    if scenario is not None:
        assert manifest['scenario'] == scenario, 'scenario differs from frozen manifest'


def emit(event, **fields):
    print(json.dumps(dict(event=event, at=utc(), **fields)), flush=True)


def run(argv, timeout=120, check=True, cwd=None, input=None):
    p = subprocess.run(list(map(str, argv)), input=input, text=True, encoding='utf-8',
                       errors='replace', capture_output=True, timeout=timeout, cwd=cwd)
    if check and p.returncode:
        raise RuntimeError(f'{Path(str(argv[0])).name}: rc={p.returncode}: {p.stderr[-1600:]} {p.stdout[-500:]}')
    return p


def parallel(fn, items, workers=8):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


def counts(n, regions, spares=False):
    extra = (40 if n > 91 else 32 if n >= 61 else 24) if spares else 0
    return {r: n // len(regions) + (i < n % len(regions))
            + extra // len(regions) + (i < extra % len(regions)) for i, r in enumerate(regions)}


def placement(candidates, n, regions):
    selected = []
    pools = {r: sorted((h for h in candidates if h['region'] == r and h['role'] != 'bastion'),
                       key=lambda h: h['id']) for r in regions}
    for node in range(n):
        region = regions[node % len(regions)]
        offset = node // len(regions)
        if offset >= len(pools[region]):
            raise RuntimeError(f'insufficient qualified hosts in {region}')
        selected.append(dict(pools[region][offset], node=node))
    assert len({h['id'] for h in selected}) == n
    return selected


def process_alive(pid):
    if os.name=='nt':
        import ctypes
        kernel=ctypes.windll.kernel32
        kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes=(ctypes.c_void_p,ctypes.c_ulong)
        kernel.CloseHandle.argtypes=(ctypes.c_void_p,)
        handle=kernel.OpenProcess(0x100000,False,int(pid))
        if not handle:return False
        try:return kernel.WaitForSingleObject(handle,0)==258
        finally:kernel.CloseHandle(handle)
    return Path(f'/proc/{pid}').exists()


def egress_addresses():
    """Raw SSH and HTTPS can use different NAT exits under split-tunnel VPNs."""
    import ipaddress
    import urllib.request
    def stun(target):
        try:
            transaction=os.urandom(12);cookie=0x2112a442
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(5);sock.sendto(struct.pack('!HHI',1,0,cookie)+transaction,target)
                data,_=sock.recvfrom(2048)
            assert data[8:20]==transaction
            offset=20
            while offset+4<=len(data):
                kind,size=struct.unpack('!HH',data[offset:offset+4]);value=data[offset+4:offset+4+size]
                offset+=4+(size+3)//4*4
                if kind in (1,0x20) and len(value)>=8 and value[1]==1:
                    value=struct.unpack('!I',value[4:8])[0] ^ (cookie if kind==0x20 else 0)
                    return str(ipaddress.IPv4Address(value))
        except Exception:return None
    ips=set(parallel(stun,[('stun.l.google.com',19302),('stun.cloudflare.com',3478)],2))-{None}
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('https://checkip.amazonaws.com',timeout=15) as response:
            ips.add(str(ipaddress.IPv4Address(response.read().decode().strip())))
    except Exception:pass
    if not ips:raise RuntimeError('cannot discover a bounded SSH source address')
    return sorted(ips)


def background_command(root,n,command):
    prefix=f'{root}/jobs/n{n}';log=f'{root}/n{n}.remote.log'
    process=command+'; code=$?; printf "%s\\n" "$code" > '+shlex.quote(prefix+'.exit')
    return ('mkdir -p '+shlex.quote(root+'/jobs')+'; if mkdir '+shlex.quote(prefix+'.claimed')+' 2>/dev/null; then '
            'nohup sh -c '+shlex.quote(process)+' > '+shlex.quote(log)+' 2>&1 < /dev/null & '
            'echo $! > '+shlex.quote(prefix+'.pid')+'; fi; '
            'for i in 1 2 3 4 5; do test -s '+shlex.quote(prefix+'.pid')+' && break; sleep 1; done; '
            'test -s '+shlex.quote(prefix+'.pid')+' && cat '+shlex.quote(prefix+'.pid'))


def native_config(protocol,n,epochs,hosts,campaign,repetition=1):
    cfg=measured.config(protocol,n,epochs,repetition,[h['ip'] for h in hosts],max(60000,60000*((n+3)//4)))
    cfg.update(name=campaign+f'-{protocol}-n{n}-r{repetition}',session_id=campaign+f'-n{n}-r{repetition}',
               max_pool=2,linger_ms=0,adaptive_production_window=protocol=='asyrand',
               production_window_min=2,production_window_max=8,recovery_interval_ms=1000)
    cfg['peers_p2p_port']={f'node{i}':9000 for i in range(n)}
    return cfg


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        assert len({m.name for m in members}) == len(members)
        for member in members:
            path = PurePosixPath(member.name)
            assert member.isfile() and not path.is_absolute() and path.parts
            assert not any(p in ('.', '..') for p in path.parts)
            assert ':' not in member.name and '\\' not in member.name
            assert destination in (destination / member.name).resolve().parents
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)


class SSH:
    def __init__(self, root, key):
        self.root, self.key = Path(root), str(key)
        self.known = str(self.root / 'known_hosts')

    def options(self):
        options = ['-i', self.key, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=45',
                '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
                '-o', 'StrictHostKeyChecking=accept-new', '-o', f'UserKnownHostsFile={self.known}']
        if os.name == 'posix':
            identity = hashlib.sha256(str(self.root).encode()).hexdigest()[:10]
            options += ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=600',
                        '-o', f'ControlPath=/tmp/t{identity}-%C']
        return options

    def call(self, host, command, timeout=90, check=True, input=None):
        return run(['ssh', *self.options(), 'ubuntu@' + host['ip'], command],
                   timeout=timeout, check=check, input=input)

    def put(self, host, local, remote):
        return run(['scp', '-q', *self.options(), str(local), f'ubuntu@{host["ip"]}:{remote}'], timeout=600)

    def get(self, host, remote, local):
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        return run(['scp', '-q', *self.options(), f'ubuntu@{host["ip"]}:{remote}', str(local)], timeout=1800)

    def stream(self, host, command, local):
        """Avoid a second archive-sized evidence copy on the bastion."""
        partial = Path(str(local)+'.partial')
        assert not Path(local).exists() and not partial.exists(), 'preserve existing evidence'
        with partial.open('xb') as output:
            p = subprocess.run(['ssh', *self.options(), 'ubuntu@'+host['ip'], command],
                               stdout=output, stderr=subprocess.PIPE, timeout=7200)
        if p.returncode:
            raise RuntimeError('evidence stream failed: '+p.stderr.decode(errors='replace')[-800:])
        partial.replace(local)


class Fleet:
    """Only exact campaign tags may be adopted, changed or terminated."""
    driver_filename = 'aws_bench.py'
    scenario = 'single'
    prune_during_job = False

    def __init__(self, root):
        import boto3
        from botocore.config import Config
        self.root = Path(root).resolve()
        self.plan = read(self.root / 'plan.json')
        self.name = self.plan['campaign']
        assert re.fullmatch(r'tyche-aws-[a-z0-9-]+', self.name)
        settings = read(self.plan['settings_path'])
        self.key_name = settings['key']['name']
        self.key = Path(settings['key']['path']).expanduser()
        if not self.key.is_absolute():
            self.key = Path(self.plan['settings_path']).parent / self.key
        self.regions = self.plan['regions']
        self.clients = {r: boto3.client('ec2', region_name=r,
                         config=Config(proxies={}, connect_timeout=12, read_timeout=35,
                                       retries={'max_attempts': 3})) for r in self.regions}
        self.data = read(self.root / 'fleet.private.json') if (self.root / 'fleet.private.json').exists() else {
            'campaign': self.name, 'instances': [], 'groups': {}, 'launches': [], 'networks': {}}
        assert self.data['campaign'] == self.name
        self.ssh = SSH(self.root, self.key)
        self.persist()

    def persist(self):
        save(self.root / 'fleet.private.json', self.data)

    def tags(self, role):
        return [{'Key': 'TycheCampaign', 'Value': self.name}, {'Key': 'Name', 'Value': self.name},
                {'Key': 'Role', 'Value': role}]

    def controller_access(self,host):
        group=self.data['groups'][host['region']][0]
        observed=self.clients[host['region']].describe_security_groups(GroupIds=[group])['SecurityGroups'][0]
        assert any(t['Key']=='TycheCampaign' and t['Value']==self.name for t in observed['Tags'])
        ips=egress_addresses()
        for ip in ips:self.ingress(host['region'],group,[dict(IpProtocol='tcp',FromPort=22,ToPort=22,
                                IpRanges=[dict(CidrIp=ip+'/32',Description='campaign-control-egress')])])
        save(self.root/'controller-egress.private.json',dict(at=utc(),addresses=ips,region=host['region'],scope='exact campaign SSH /32 only'))

    def control(self,host,command,timeout=90,check=True):
        for attempt in range(3):
            try:p=self.ssh.call(host,command,timeout=timeout,check=False)
            except (OSError,subprocess.TimeoutExpired):p=None
            if p is not None and p.returncode!=255:
                if check and p.returncode:raise RuntimeError(f'control command failed: {p.stderr[-700:]} {p.stdout[-300:]}')
                return p
            self.controller_access(host)
            time.sleep(3)
        raise RuntimeError('management SSH unavailable after exact-source reconciliation')

    def transfer_bundle(self,host,remote,n,local):
        command=shlex.join(['python3',remote+'/'+self.driver_filename,'bundle','--scenario',self.scenario,'--out',remote,'--nodes',str(n)])
        for attempt in range(3):
            partial=Path(str(local)+'.partial')
            if partial.exists():partial.rename(Path(str(partial)+f'.failed-{time.time_ns()}'))
            try:
                self.ssh.stream(host,command,local)
                return
            except Exception:
                if attempt==2:raise
                self.controller_access(host)

    def remote_job(self,host,remote,n):
        command=shlex.join(['python3','-u',remote+'/'+self.driver_filename,'remote','--scenario',self.scenario,'--out',remote,'--inventory',remote+'/inventory.json'])
        self.control(host,background_command(remote,n,command))
        deadline=time.monotonic()+36000
        prefix=remote+f'/jobs/n{n}'
        while time.monotonic()<deadline:
            # Lifecycle operations are serialized in this one parent process.
            # The detached protocol continues while unused candidates terminate.
            if self.prune_during_job and not (self.root/f'cost-cleanup-n{n}.json').exists():
                code="from pathlib import Path; import json; p=Path("+repr(remote+f'/inventory-n{n}.json')+"); print(json.dumps(json.loads(p.read_text()) if p.exists() else []))"
                selected=json.loads(self.control(host,'python3 -c '+shlex.quote(code)).stdout)
                if selected:self.prune_unused(n,selected,host)
            status=self.control(host,'if test -f '+prefix+'.exit; then echo exit:$(cat '+prefix+'.exit); '
                                'elif kill -0 $(cat '+prefix+'.pid) 2>/dev/null; then echo running; else echo lost; fi').stdout.strip()
            if status.startswith('exit:'):
                self.ssh.get(host,remote+f'/n{n}.remote.log',self.root/f'n{n}.controller.log')
                return int(status.split(':')[1])
            if status=='lost':raise RuntimeError('detached size controller disappeared without durable exit')
            time.sleep(20)
        raise RuntimeError('detached size controller deadline exceeded')

    def prune_unused(self,n,selected,gateway):
        assert len(selected)==n and len({h['id'] for h in selected})==n
        assert all(h['role']=='candidate' for h in selected)
        keep={h['id'] for h in selected}|{gateway['id']}
        rows=self.refresh();assert keep<={h['id'] for h in rows}
        extras=[h for h in rows if h['role']=='candidate' and h['id'] not in keep]
        receipt=dict(valid=False,n=n,before=len(rows),started_at=utc(),kept_instance_ids=sorted(keep),
                     terminated_instance_ids=[h['id'] for h in extras],scope='exact campaign tagged candidates outside fixed committee')
        save(self.root/f'cost-cleanup-n{n}.json',receipt)
        volumes={}
        for region in self.regions:
            ids=[h['id'] for h in extras if h['region']==region]
            if not ids:continue
            c=self.clients[region]
            observed=[i for batch in c.describe_instances(InstanceIds=ids)['Reservations'] for i in batch['Instances']]
            assert all(any(t['Key']=='TycheCampaign' and t['Value']==self.name for t in i['Tags']) for i in observed)
            attached=c.describe_volumes(Filters=[dict(Name='attachment.instance-id',Values=ids)])['Volumes']
            assert all(any(t['Key']=='TycheCampaign' and t['Value']==self.name for t in v['Tags']) for v in attached)
            volumes[region]=[v['VolumeId'] for v in attached]
            c.terminate_instances(InstanceIds=ids)
        deadline=time.monotonic()+600
        while True:
            remaining=[h for h in self.refresh() if h['id'] in receipt['terminated_instance_ids']]
            if not remaining:break
            if time.monotonic()>deadline:raise RuntimeError('unused candidate termination unconfirmed')
            time.sleep(5)
        for attempt in range(24):
            remaining_volumes=[v['VolumeId'] for region,ids in volumes.items() if ids
                for v in self.clients[region].describe_volumes(Filters=[dict(Name='volume-id',Values=ids)])['Volumes']]
            if not remaining_volumes:break
            time.sleep(5)
        final=self.refresh();assert keep<={h['id'] for h in final}
        receipt.update(valid=not remaining_volumes,completed_at=utc(),after=len(final),remaining_unused_volumes=remaining_volumes)
        save(self.root/f'cost-cleanup-n{n}.json',receipt);assert receipt['valid']
        emit('unused-spares-released',n=n,released=len(extras),remaining=len(final))

    def refresh(self):
        def one(region):
            rows = self.clients[region].describe_instances(Filters=[
                {'Name': 'tag:TycheCampaign', 'Values': [self.name]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped', 'shutting-down']}])
            return [dict(id=i['InstanceId'], region=region, ip=i.get('PublicIpAddress'),
                         private_ip=i.get('PrivateIpAddress'), state=i['State']['Name'],
                         role=next(t['Value'] for t in i['Tags'] if t['Key'] == 'Role'),
                         type=i['InstanceType']) for r in rows['Reservations'] for i in r['Instances']]
        rows = [h for batch in parallel(one, self.regions, 4) for h in batch]
        self.data['instances'] = rows
        self.persist()
        return rows

    def discover(self):
        def one(region):
            c = self.clients[region]
            c.describe_key_pairs(KeyNames=[self.key_name])
            zones = {o['Location'] for o in c.describe_instance_type_offerings(LocationType='availability-zone',
                Filters=[{'Name': 'instance-type', 'Values': [self.plan['instance_type']]}])['InstanceTypeOfferings']}
            subnets = [s for s in c.describe_subnets(Filters=[{'Name': 'default-for-az', 'Values': ['true']}])['Subnets']
                       if s['AvailabilityZone'] in zones and s['MapPublicIpOnLaunch'] and s['AvailableIpAddressCount'] >= 24]
            if not subnets:
                raise RuntimeError('no public supported default subnet: ' + region)
            images = c.describe_images(Owners=['099720109477'], Filters=[
                {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
                {'Name': 'state', 'Values': ['available']}, {'Name': 'architecture', 'Values': ['x86_64']}])['Images']
            image = max(images, key=lambda i: i['CreationDate'])
            return region, dict(subnets=sorted(subnets, key=lambda s: s['AvailabilityZone']),
                                image=image['ImageId'], image_name=image['Name'], device=image['RootDeviceName'])
        self.data['networks'] = dict(parallel(one, self.regions, 4))
        self.persist()

    def groups(self, region):
        c = self.clients[region]
        network = self.data['networks'][region]
        vpc = network['subnets'][0]['VpcId']
        existing = c.describe_security_groups(Filters=[{'Name': 'tag:TycheCampaign', 'Values': [self.name]}])['SecurityGroups']
        found = {g['GroupName']: g['GroupId'] for g in existing}
        ids = []
        for suffix in ('ssh', 'peer0', 'peer1', 'peer2', 'peer3'):
            name = f'{self.name}-{suffix}'
            if name not in found:
                found[name] = c.create_security_group(GroupName=name, VpcId=vpc, Description='Tyche scoped native AWS experiment',
                    TagSpecifications=[{'ResourceType': 'security-group', 'Tags': self.tags(suffix)}])['GroupId']
            ids.append(found[name])
        with LOCK:
            self.data['groups'][region] = ids
            self.persist()
        return ids

    def ingress(self, region, group, rules):
        if not rules:
            return
        try:
            self.clients[region].authorize_security_group_ingress(GroupId=group, IpPermissions=rules)
        except Exception as error:
            if getattr(error, 'response', {}).get('Error', {}).get('Code') != 'InvalidPermission.Duplicate':
                raise

    def launch(self, region, amount, role='candidate'):
        c, network = self.clients[region], self.data['networks'][region]
        groups = self.groups(region)
        public_key = (self.root / 'control-key.pub').read_text().strip()
        assert public_key.startswith('ssh-ed25519 ') and '\n' not in public_key
        lifetime = 720 if role == 'bastion' else 240
        user_data = ('#!/bin/bash\nset -eu\n'
                     'install -d -o ubuntu -g ubuntu -m 700 /home/ubuntu/.ssh\n'
                     f'echo {shlex.quote(public_key)} >> /home/ubuntu/.ssh/authorized_keys\n'
                     'chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys\n'
                     'chmod 600 /home/ubuntu/.ssh/authorized_keys\n'
                     f'shutdown -P +{lifetime}\n')
        for offset in range(0, amount, 8):
            batch = min(8, amount - offset)
            last_error = None
            for subnet in network['subnets']:
                if subnet['VpcId'] != network['subnets'][0]['VpcId']:
                    continue
                token = hashlib.sha256(f'{self.name}:{region}:{role}:{len(self.data["launches"])}:{subnet["SubnetId"]}'.encode()).hexdigest()
                with LOCK:
                    self.data['launches'].append(dict(token=token, region=region, count=batch, role=role, at=utc()))
                    self.persist()
                request = dict(ImageId=network['image'], InstanceType=self.plan['instance_type'], KeyName=self.key_name,
                    MinCount=batch, MaxCount=batch, ClientToken=token,
                    NetworkInterfaces=[dict(DeviceIndex=0, SubnetId=subnet['SubnetId'], AssociatePublicIpAddress=True, Groups=groups)],
                    BlockDeviceMappings=[dict(DeviceName=network['device'], Ebs=dict(VolumeType='gp3', VolumeSize=self.plan['volume_gb'], DeleteOnTermination=True))],
                    CreditSpecification={'CpuCredits': 'unlimited'}, InstanceInitiatedShutdownBehavior='terminate',
                    MetadataOptions={'HttpTokens': 'required'}, UserData=user_data,
                    TagSpecifications=[dict(ResourceType=kind, Tags=self.tags(role)) for kind in ('instance', 'volume')])
                try:
                    c.run_instances(**request)
                    break
                except Exception as error:
                    # Unknown outcomes are reconciled by the same idempotency token, never a fresh launch.
                    found = c.describe_instances(Filters=[{'Name': 'client-token', 'Values': [token]}])['Reservations']
                    if sum(len(r['Instances']) for r in found) == batch:
                        break
                    code = getattr(error, 'response', {}).get('Error', {}).get('Code')
                    if code not in ('InsufficientInstanceCapacity', 'Unsupported', 'UnsupportedOperation'):
                        raise
                    last_error = error
            else:
                raise RuntimeError(f'capacity unavailable: {region}') from last_error
        emit('provisioned', region=region, amount=amount, role=role)

    def authorize(self, controller_ip=None):
        hosts = self.refresh()
        bastions = [h for h in hosts if h['role'] == 'bastion' and h['ip']]
        gateway = bastions[0] if bastions else None
        addresses = sorted({h['ip'] for h in hosts if h['ip'] and h['role'] != 'bastion'})
        assert len(addresses) <= 199
        for region, groups in self.data['groups'].items():
            existing = self.clients[region].describe_security_groups(GroupIds=groups)['SecurityGroups']
            known = {g['GroupId']: g['IpPermissions'] for g in existing}
            ssh_ips = {gateway['ip']} if gateway else set()
            if gateway and gateway['region'] == region:
                ssh_ips.add(gateway['private_ip'])
            if controller_ip and (not gateway or gateway['region'] == region):
                ssh_ips.add(controller_ip)
            for ip in sorted(ssh_ips):
                if not any(p.get('FromPort')==22 and any(x['CidrIp']==ip+'/32' for x in p.get('IpRanges',[])) for p in known[groups[0]]):
                    self.ingress(region, groups[0], [dict(IpProtocol='tcp', FromPort=22, ToPort=22,
                                                        IpRanges=[dict(CidrIp=ip+'/32')])])
            # Only called between sizes, with no protocol running. Replace peer
            # shards as one fixed inventory rather than accumulating stale rules.
            for group in groups[1:]:
                if known[group]:
                    self.clients[region].revoke_security_group_ingress(GroupId=group,IpPermissions=known[group])
            self.ingress(region, groups[1], [dict(IpProtocol='tcp', FromPort=9000, ToPort=9000,
                                                UserIdGroupPairs=[{'GroupId': groups[1]}])])
            for shard, group in enumerate(groups[1:]):
                ranges=[dict(CidrIp=ip+'/32') for ip in addresses[shard*50:(shard+1)*50]]
                if ranges:self.ingress(region,group,[dict(IpProtocol='tcp',FromPort=9000,ToPort=9000,IpRanges=ranges)])
        return gateway

    def grow(self, n):
        targets = counts(n, self.regions, True)
        current = self.refresh()
        for region in self.regions:
            total = sum(h['region'] == region for h in current)
            if total > targets[region]:
                raise RuntimeError('unplanned existing campaign capacity')
        parallel(lambda r: self.launch(r, targets[r] - sum(h['region'] == r for h in current))
                 if targets[r] > sum(h['region'] == r for h in current) else None, self.regions, 4)
        self.wait_running(targets)
        self.authorize(self.plan['controller_ip'])
        assert len(self.refresh()) <= sum(targets.values()) <= 161

    def wait_running(self,expected):
        until = time.monotonic() + 600
        while time.monotonic() < until:
            rows = self.refresh()
            actual={r:sum(h['region']==r for h in rows) for r in self.regions}
            if all(actual[r]==expected.get(r,0) for r in self.regions) and all(h['state'] == 'running' and h['ip'] for h in rows):
                return rows
            time.sleep(8)
        raise RuntimeError('EC2 running/address timeout')

    def telemetry(self,label):
        import boto3
        from botocore.config import Config
        rows=self.refresh()
        def one(region):
            ids=[h['id'] for h in rows if h['region']==region]
            if not ids:return region,{}
            try:
                spec=self.clients[region].describe_instance_credit_specifications(InstanceIds=ids)
                queries=[]
                for index,identity in enumerate(ids):
                    for metric in ('CPUCreditBalance','CPUSurplusCreditBalance','CPUSurplusCreditsCharged','CPUUtilization'):
                        queries.append(dict(Id=f'm{index}_{metric.lower()}',MetricStat=dict(
                            Metric=dict(Namespace='AWS/EC2',MetricName=metric,Dimensions=[dict(Name='InstanceId',Value=identity)]),
                            Period=300,Stat='Average'),ReturnData=True))
                cw=boto3.client('cloudwatch',region_name=region,config=Config(proxies={},connect_timeout=12,read_timeout=35))
                at=datetime.now(timezone.utc)
                data=cw.get_metric_data(MetricDataQueries=queries,StartTime=at-timedelta(hours=8),EndTime=at)
                return region,json.loads(json.dumps(dict(specification=spec,cloudwatch=data),default=str))
            except Exception as error:
                return region,dict(error=getattr(error,'response',{}).get('Error',{}).get('Code',type(error).__name__))
        save(self.root/f'credits-{label}.json',dict(parallel(one,self.regions,4)))

    def terminate(self):
        rows = self.refresh()
        for region in self.regions:
            ids = [h['id'] for h in rows if h['region'] == region]
            if ids:
                self.clients[region].terminate_instances(InstanceIds=ids)
        until = time.monotonic() + 600
        while self.refresh() and time.monotonic() < until:
            time.sleep(8)
        if self.refresh():
            raise RuntimeError('campaign instance cleanup incomplete')
        errors = []
        for region, groups in self.data['groups'].items():
            c = self.clients[region]
            for group in groups:
                permissions = c.describe_security_groups(GroupIds=[group])['SecurityGroups'][0]['IpPermissions']
                if permissions:
                    c.revoke_security_group_ingress(GroupId=group, IpPermissions=permissions)
            for group in groups:
                for attempt in range(12):
                    try:
                        c.delete_security_group(GroupId=group)
                        break
                    except Exception:
                        if attempt == 11:
                            errors.append(group)
                        time.sleep(5)
        for attempt in range(12):
            volumes=[]
            for region in self.regions:
                volumes.extend(self.clients[region].describe_volumes(Filters=[{'Name': 'tag:TycheCampaign', 'Values': [self.name]}])['Volumes'])
            if not volumes:break
            time.sleep(5)
        receipt = dict(valid=not errors and not volumes, checked_at=utc(), remaining_instances=[],
                       remaining_security_groups=errors, remaining_volumes=[v['VolumeId'] for v in volumes])
        save(self.root/'cleanup-audit.json', receipt)
        assert receipt['valid'], receipt


PROBE = r'''
import json,os,pathlib,platform,subprocess
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
assert os.cpu_count()==2 and 3600*1024<int(mem['MemTotal'].split()[0])<4300*1024
assert int(mem['SwapTotal'].split()[0])==0
assert pathlib.Path('/sys/fs/cgroup/cgroup.controllers').exists()
assert tuple(map(int,platform.release().split('-')[0].split('.')[:2])) >= (5,19), 'kernel lacks native memory.peak accounting'
assert not subprocess.check_output(['ss','-H','-ltn','sport','=',':9000'],text=True).strip()
print(json.dumps(dict(cpu_count=os.cpu_count(),memory_kib=int(mem['MemTotal'].split()[0]),kernel=platform.release(),swap_kib=0)))
'''


MESH_SERVER = r'''
import socketserver
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=256
class Handler(socketserver.BaseRequestHandler):
    def handle(self): self.request.sendall(b'tyche-mesh-v1\n')
Server(('0.0.0.0',9000),Handler).serve_forever()
'''


MESH_CLIENT = r'''
import concurrent.futures,json,socket,sys
hosts=json.loads(sys.argv[1])
def check(h):
    try:
        with socket.create_connection((h['ip'],9000),timeout=4) as s:
            s.settimeout(4);assert s.makefile('rb').readline(64)==b'tyche-mesh-v1\n'
        return h['id'],True
    except Exception:return h['id'],False
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as p: print(json.dumps(dict(p.map(check,hosts))))
'''


def remote_ready(root, inventory):
    ssh = SSH(root, root/'control-key')
    base = f'/home/ubuntu/{inventory["campaign"]}'
    candidates = [h for h in inventory['candidates'] if h['role'] != 'bastion']
    def qualify(h):
        for attempt in range(3):
            try:
                probe = read_remote(ssh, h, 'python3 -c ' + shlex.quote(PROBE))
                ssh.call(h, 'sudo shutdown -c >/dev/null 2>&1; sudo shutdown -P +240; mkdir -p '+shlex.quote(base), timeout=30)
                return dict(h, preflight=probe)
            except Exception as error:
                if attempt == 2:
                    return dict(h, qualification_error=type(error).__name__)
                time.sleep(6)
    ready = parallel(qualify, candidates)
    save(root/f'qualification-n{inventory["n"]}.json', ready)
    ready = [h for h in ready if 'qualification_error' not in h]
    for region, need in counts(inventory['n'], inventory['regions']).items():
        assert sum(h['region'] == region for h in ready) >= need, f'SSH candidates missing: {region}'
    script = base+'/mesh.py'
    def listen(h):
        ssh.call(h, 'cat > '+shlex.quote(script), input=MESH_SERVER)
        ssh.call(h, f'nohup python3 {shlex.quote(script)} > {shlex.quote(base+"/mesh.log")} 2>&1 < /dev/null & echo $! > {shlex.quote(base+"/mesh.pid")}')
    parallel(listen, ready)
    time.sleep(2)
    try:
        edges = dict(parallel(lambda h: (h['id'], read_remote(ssh, h,
            'python3 -c '+shlex.quote(MESH_CLIENT)+' '+shlex.quote(json.dumps(ready)))), ready))
        save(root/f'mesh-n{inventory["n"]}.json', edges)
        # Preserve regional placement; choose an all-to-all compatible committee.
        remaining = ready[:]
        for attempt in range(len(ready)):
            selected = placement(remaining, inventory['n'], inventory['regions'])
            bad = [(a,b) for a in selected for b in selected if a['id'] != b['id'] and not edges[a['id']].get(b['id'],False)]
            if not bad:
                return selected
            failures = {h['id']:sum(h['id'] in (a['id'],b['id']) for a,b in bad) for h in selected}
            removable = [h for h in selected if failures[h['id']]>0 and sum(x['region']==h['region'] for x in remaining) > counts(inventory['n'],inventory['regions'])[h['region']]]
            if not removable:
                raise RuntimeError('no full compatible regional mesh')
            discard = max(removable,key=lambda h:failures[h['id']])
            remaining = [h for h in remaining if h['id'] != discard['id']]
        raise RuntimeError('mesh selection exhausted')
    finally:
        parallel(lambda h: ssh.call(h, f'test ! -f {base}/mesh.pid || kill $(cat {base}/mesh.pid); true', check=False), ready)


def read_remote(ssh, host, cmd):
    return json.loads(ssh.call(host, cmd).stdout)


def worker_launcher(base, cell, node, protocol, epochs, unit, procs):
    folder = f'{base}/{cell}/node{node}'
    binary = f'{base}/payload/bin/{protocol}'
    command = [binary, '-config', folder+'/config.json', '-node', f'node{node}', '-transport', 'tcp']
    if protocol == 'grandline':
        command += ['-setup-file', folder+'/setup.json']
    if protocol == 'asyrand':
        command += ['-history', folder+'/history.json']
    env = dict(GOMAXPROCS=str(procs), GOMEMLIMIT='2800MiB', TYCHE_CRYPTO_PARALLELISM='2',
               TYCHE_ASY_PREDECRYPT='1', TYCHE_ASY_CONSUMER_PRIORITY='1', TYCHE_BENCHMARK='1',
               TYCHE_BENCHMARK_NODE=f'node{node}', TYCHE_PROFILE_NODE='node0',
               TYCHE_BENCHMARK_DIR=folder, TYCHE_VERIFY_BARRIER=folder+'/verify-start')
    return ('#!/bin/bash\nset -eu\ncd '+shlex.quote(folder)+'\n'
            'finish() { code=$?; trap - EXIT; printf "%s\\n" "$code" > node.exit; chown -R ubuntu:ubuntu '+shlex.quote(folder)+'; exit "$code"; }\ntrap finish EXIT\n'
            'mount --make-rprivate /\n'
            'cg=$(cut -d: -f3 /proc/self/cgroup)\n'
            'mount --bind "/sys/fs/cgroup$cg" /sys/fs/cgroup\n'
            'cat /proc/self/cgroup > cgroup-path.txt\ncat /sys/fs/cgroup/cpu.max > cpu.max\n'
            'test -f /sys/fs/cgroup/memory.peak\ntouch ready\n'
            'while [ ! -f start ]; do sleep 0.1; done\nset +e\n'
            +shlex.join(['env', *(f'{k}={v}' for k,v in env.items()), *command])+' > stdout.log 2>&1\n'
            'code=$?\ncat /sys/fs/cgroup/cpu.stat > cpu.stat\n'
            'cat /sys/fs/cgroup/memory.events > memory.events\n'
            'cat /sys/fs/cgroup/memory.peak > memory.peak\n'
            'exit "$code"\n')


def collect_nodes(root,out,active,ssh):
    def one(h):
        node=h['node'];archive=out/f'node{node}.tar.gz';dest=out/f'node{node}'
        if archive.exists() and dest.exists():return
        remote=h['folder']+'.tar.gz'
        # The archive includes the full durable AsyRand history, not only its hash.
        script="import pathlib,tarfile,hashlib,json; p=pathlib.Path("+repr(h['folder'])+"); a=p.with_name(p.name+'.tar.gz'); t=tarfile.open(a,'w:gz',compresslevel=1); [(t.add(f,arcname=f.name,recursive=False)) for f in sorted(p.iterdir()) if f.is_file()]; t.close(); print(json.dumps({'sha256':hashlib.sha256(a.read_bytes()).hexdigest(),'bytes':a.stat().st_size}))"
        receipt=read_remote(ssh,h,'sudo python3 -c '+shlex.quote(script))
        ssh.call(h,'sudo chown ubuntu:ubuntu '+shlex.quote(remote))
        ssh.get(h,remote,archive);assert sha(archive)==receipt['sha256']
        if not dest.exists():
            # Keep histories compressed to bound bastion disk use; extract measurements/logs only.
            with tarfile.open(archive) as tar:
                members=tar.getmembers();assert len({m.name for m in members})==len(members)
                for m in members:assert m.isfile() and len(PurePosixPath(m.name).parts)==1 and ':' not in m.name and '\\' not in m.name
                dest.mkdir()
                hashes={}
                for m in members:
                    with tar.extractfile(m) as source:
                        digest=hashlib.sha256()
                        if m.name=='history.json':
                            for chunk in iter(lambda:source.read(2**20),b''):digest.update(chunk)
                        else:
                            with (dest/m.name).open('xb') as target:
                                for chunk in iter(lambda:source.read(2**20),b''):digest.update(chunk);target.write(chunk)
                    hashes[m.name]=digest.hexdigest()
        else:hashes={}
        save(out/f'node{node}.receipt.json',dict(**receipt,files_sha256=hashes,instance_id=h['id']))
    parallel(one,active,4)


def bundle(root,n):
    """Tar to SSH stdout; full histories stay in their verified node archives."""
    files=[]
    results=root/'results'
    if results.exists():
        for folder in sorted(results.iterdir()):
            if folder.is_dir() and (n==0 or f'-n{n}-' in folder.name or (n==16 and folder.name.startswith('smoke-'))):
                files.extend(p for p in sorted(folder.rglob('*')) if p.is_file())
    files.extend(p for p in sorted(root.glob('*.json')) if p.name not in {'inventory.json'} and
                 not p.name.startswith('bundle-') and
                 (n==0 or f'n{n}.' in p.name or p.name in ('status.json','payload-manifest.json','smoke-valid.json')))
    if n in (0,16) and (root/'attempts').exists():
        files.extend(p for p in sorted((root/'attempts').rglob('*')) if p.is_file())
    class Writer:
        def __init__(self):self.digest=hashlib.sha256();self.size=0
        def write(self,data):
            self.digest.update(data);self.size+=len(data)
            return sys.stdout.buffer.write(data)
    output=Writer()
    with tarfile.open(fileobj=output,mode='w|') as tar:
        for file in files:
            assert not file.is_symlink()
            tar.add(file,arcname=file.relative_to(root).as_posix(),recursive=False)
    sys.stdout.buffer.flush()
    save(root/f'bundle-n{n}.receipt.json',dict(valid=True,sha256=output.digest.hexdigest(),bytes=output.size,
                                             files=len(files),n=n,at=utc()))


def run_campaign(args, driver):
    root=Path(args.out).resolve();verify_controller(driver.__file__,root,driver.scenario)
    fleet=driver.Fleet(root);plan=fleet.plan
    resume=args.action=='resume'
    if (root/'controller.pid').exists():
        assert resume and not process_alive(int((root/'controller.pid').read_text())), 'controller already alive or not explicitly reconciled'
        assert read(root/'status.json')['state'] in ('interrupted','failed')
    (root/'controller.pid').write_text(str(os.getpid()))
    save(root/'status.json',dict(state='preparing',pid=os.getpid(),updated_at=utc()))
    gateway=None;complete=False
    try:
        if not resume:
            fleet.discover()
            assert not fleet.refresh(),'new campaign must not adopt a pre-existing fleet silently'
            fleet.launch(plan['bastion_region'],1,'bastion');fleet.wait_running({plan['bastion_region']:1})
            gateway=fleet.authorize(plan['controller_ip'])
        else:
            rows=fleet.refresh();gateway=fleet.data['bastion']
            assert sum(h['role']=='bastion' and h['id']==gateway['id'] and h['state']=='running' for h in rows)==1
            assert all(h['type']==plan['instance_type'] for h in rows)
        for attempt in range(20):
            try:
                p=fleet.control(gateway,'cloud-init status --wait >/dev/null; uname -r',timeout=90,check=False)
                if p.returncode==0:break
            except (OSError,subprocess.TimeoutExpired):pass
            time.sleep(8)
        else:raise RuntimeError('bastion SSH unavailable')
        probe=json.loads(fleet.control(gateway,'python3 -c '+shlex.quote(PROBE)).stdout)
        save(root/'bastion-preflight.json',probe)
        remote='/home/ubuntu/'+plan['campaign'];fleet.data['bastion']=gateway;fleet.persist()
        fleet.control(gateway,'mkdir -p '+remote+'/payload')
        for local in (root/'protocol.tar.gz',root/'payload-manifest.json',root/'control-key',*controller_files(driver.__file__)):
            fleet.ssh.put(gateway,local,remote+'/'+local.name)
        fleet.control(gateway,'chmod 600 '+remote+'/control-key; tar -xzf '+remote+'/protocol.tar.gz -C '+remote+'/payload; chmod +x '+remote+'/payload/bin/*')
        for n in SIZES:
            if (root/f'n{n}.local-audit.json').exists():
                assert read(root/f'n{n}.local-audit.json')['valid']
                continue
            save(root/'status.json',dict(state='running',phase='provision',n=n,pid=os.getpid(),updated_at=utc()))
            fleet.grow(n)
            fleet.telemetry(f'n{n}-before')
            inventory=dict(campaign=plan['campaign'],n=n,regions=fleet.regions,candidates=fleet.refresh())
            path=root/f'inventory-n{n}.private.json';save(path,inventory)
            fleet.ssh.put(gateway,path,remote+'/inventory.json')
            # Execute on the bastion: payload fanout, protocol processes and evidence collection.
            emit('bastion-size-start',n=n,candidates=len(inventory['candidates']))
            save(root/'status.json',dict(state='running',phase='bastion',n=n,pid=os.getpid(),updated_at=utc()))
            exit_code=fleet.remote_job(gateway,remote,n)
            fleet.transfer_bundle(gateway,remote,n,root/f'n{n}.tar')
            fleet.ssh.get(gateway,remote+f'/bundle-n{n}.receipt.json',root/f'n{n}.receipt.json')
            receipt=read(root/f'n{n}.receipt.json')
            assert sha(root/f'n{n}.tar')==receipt['sha256']
            assert exit_code==0,'bastion size controller failed; evidence preserved'
            driver.audit_stage(root,n)
            fleet.telemetry(f'n{n}-after')
            emit('size-collected',n=n,archive_bytes=receipt['bytes'],sha256=receipt['sha256'])
            # A verified local copy exists before reclaiming duplicate bastion stage bytes.
            cleanup="import pathlib; r=pathlib.Path("+repr(remote)+"); n="+str(n)+"; [(p.unlink()) for d in (r/'results').iterdir() if d.is_dir() and f'-n{n}-' in d.name for p in d.glob('node*.tar.gz')]"
            fleet.control(gateway,'python3 -c '+shlex.quote(cleanup))
        complete=True
    except BaseException:
        save(root/'failure.json',dict(at=utc(),traceback=traceback.format_exc()))
        emit('campaign-failed',detail='see private failure.json; collecting before scoped cleanup')
        raise
    finally:
        if gateway:
            try:
                remote='/home/ubuntu/'+plan['campaign']
                fleet.transfer_bundle(gateway,remote,0,root/'recovery.tar')
                fleet.ssh.get(gateway,remote+'/bundle-n0.receipt.json',root/'recovery.receipt.json')
                assert sha(root/'recovery.tar')==read(root/'recovery.receipt.json')['sha256']
            except Exception as error:save(root/'recovery-failure.json',dict(error=type(error).__name__,at=utc()))
        fleet.terminate()
        save(root/'status.json',dict(state='complete' if complete else 'failed',phase='collected' if complete else 'preserved',pid=os.getpid(),updated_at=utc()))
        emit('campaign-finished',complete=complete,cleanup=read(root/'cleanup-audit.json')['valid'])
    if complete:driver.summarize(root)
