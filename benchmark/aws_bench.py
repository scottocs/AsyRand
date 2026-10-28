"""Unified native AWS campaigns and compact-result commands.

Select --scenario single, silent or repeat for controller actions.
Completed campaigns continue to use their own immutable archived controllers.
"""
from __future__ import annotations
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import statistics
import sys
import tarfile
import time
import traceback

import aws_common as common
import bench_results as compact
import docker_bench as measured
from aws_common import (SSH, PROBE, emit, run, parallel, counts, placement,
                        process_alive, native_config, safe_extract, remote_ready,
                        read_remote, worker_launcher)
from bench_results import REPO, SIZES, utc, save, read, sha, read_csv, write_csv


class SilentFleet(common.Fleet):
    scenario = 'silent'
    prune_during_job = True


class RepeatFleet(common.Fleet):
    scenario = 'repeat'

    def remote_job(self, host, remote, n):
        command = shlex.join(['python3', '-u', remote + '/aws_bench.py', 'remote', '--scenario', 'repeat', '--out', remote, '--inventory', remote + '/inventory.json'])
        self.control(host, common.background_command(remote, n, command))
        prefix = remote + f'/jobs/n{n}'
        deadline = time.monotonic() + 14400
        while time.monotonic() < deadline:
            if not (self.root / f'cost-cleanup-n{n}.json').exists():
                code = 'from pathlib import Path; import json; p=Path(' + repr(remote + f'/inventory-n{n}.json') + '); print(json.dumps(json.loads(p.read_text()) if p.exists() else []))'
                selected = json.loads(self.control(host, 'python3 -c ' + shlex.quote(code)).stdout)
                if selected:
                    self.prune_unused(n, selected, host)
            status = self.control(host, 'if test -f ' + prefix + '.exit; then echo exit:$(cat ' + prefix + '.exit); elif kill -0 $(cat ' + prefix + '.pid) 2>/dev/null; then echo running; else echo lost; fi').stdout.strip()
            if status.startswith('exit:'):
                p = self.control(host, 'tail -c 65536 ' + shlex.quote(remote + f'/n{n}.remote.log'), check=False)
                (self.root / f'n{n}.controller.log').write_text(p.stdout, encoding='utf-8')
                return int(status.split(':')[1])
            if status == 'lost':
                raise RuntimeError('detached size job disappeared without durable exit')
            time.sleep(20)
        raise RuntimeError('size job exceeded four-hour deadline')

    def release_workers(self, n, gateway):
        """Terminate exact-tag candidates and their volumes before any bundle transfer."""
        rows = self.refresh()
        workers = [h for h in rows if h['role'] == 'candidate']
        assert any((h['id'] == gateway['id'] and h['role'] == 'bastion' for h in rows))
        audit = dict(valid=False, n=n, started_at=utc(), instance_ids=[h['id'] for h in workers], reason='results verified on bastion; worker release precedes local bundle download')
        save(self.root / f'worker-release-n{n}.json', audit)
        volumes = {}

        def terminate_region(region):
            ids = [h['id'] for h in workers if h['region'] == region]
            if not ids:
                return
            c = self.clients[region]
            observed = [i for r in c.describe_instances(InstanceIds=ids)['Reservations'] for i in r['Instances']]
            assert all((any((t['Key'] == 'TycheCampaign' and t['Value'] == self.name for t in i['Tags'])) for i in observed))
            attached = c.describe_volumes(Filters=[dict(Name='attachment.instance-id', Values=ids)])['Volumes']
            assert all((any((t['Key'] == 'TycheCampaign' and t['Value'] == self.name for t in v['Tags'])) for v in attached))
            volumes[region] = [v['VolumeId'] for v in attached]
            c.terminate_instances(InstanceIds=ids)
        parallel(terminate_region, self.regions, 8)
        deadline = time.monotonic() + 600
        while any((h['role'] == 'candidate' for h in self.refresh())):
            if time.monotonic() > deadline:
                raise RuntimeError('worker termination incomplete')
            time.sleep(5)
        for attempt in range(24):
            remaining = [v['VolumeId'] for (region, ids) in volumes.items() if ids for v in self.clients[region].describe_volumes(Filters=[dict(Name='volume-id', Values=ids)])['Volumes']]
            if not remaining:
                break
            time.sleep(5)
        final = self.refresh()
        assert len(final) == 1 and final[0]['id'] == gateway['id']
        audit.update(valid=not remaining, completed_at=utc(), remaining_instances=1, remaining_worker_volumes=remaining)
        save(self.root / f'worker-release-n{n}.json', audit)
        assert audit['valid']
        emit('workers-released-before-download', n=n, released=len(workers), remaining=1)

    def download(self, host, remote, n, receipt):
        assert read(self.root / f'worker-release-n{n}.json')['valid']
        path = self.root / f'n{n}.tar.gz'
        if path.exists():
            assert sha(path) == receipt['sha256']
            return
        save(self.root / f'transfer-n{n}.json', dict(started_at=utc(), worker_release_confirmed=True, bytes=receipt['bytes']))
        command = 'cat ' + shlex.quote(remote + f'/n{n}.tar.gz')
        for attempt in range(3):
            partial = Path(str(path) + '.partial')
            if partial.exists():
                partial.rename(Path(str(partial) + f'.failed-{time.time_ns()}'))
            try:
                assert not path.exists() and (not partial.exists())
                with partial.open('xb') as stream:
                    process = common.subprocess.run(['ssh', *self.ssh.options(), 'ubuntu@' + host['ip'], command], stdout=stream, stderr=common.subprocess.PIPE, timeout=300)
                if process.returncode:
                    raise RuntimeError('compact evidence SSH transfer failed: ' + process.stderr.decode(errors='replace')[-800:])
                partial.replace(path)
                assert path.stat().st_size == receipt['bytes'] and sha(path) == receipt['sha256']
                return
            except Exception:
                if attempt == 2:
                    raise
                self.controller_access(host)


class Campaign:
    __file__ = __file__
    scenario = 'single'
    protocols = compact.PROTOCOLS
    repetitions = (1,)
    Fleet = common.Fleet
    native_config = staticmethod(native_config)
    collect_nodes = staticmethod(common.collect_nodes)
    bundle = staticmethod(common.bundle)

    def run_campaign(self, args):
        return common.run_campaign(args, self)


class SingleCampaign(Campaign):
    version = 'native-v2a'

    def remote_cell(self, root, inventory, hosts, protocol, epochs=600, smoke=False):
        n = len(hosts)
        cell = ('smoke-' if smoke else '') + f'{protocol}-n{n}-r1'
        out = root / 'results' / cell
        if (out / 'validation.json').exists():
            assert read(out / 'validation.json')['run_valid']
            return
        if out.exists():
            raise RuntimeError('preserve incomplete cell; explicit reconciliation needed: ' + cell)
        out.mkdir(parents=True)
        ssh = SSH(root, root / 'control-key')
        base = '/home/ubuntu/' + inventory['campaign']
        cfg = native_config(protocol, n, epochs, hosts, inventory['campaign'])
        procs = 2 if protocol in ('spurt', 'grandline') and n == 16 else 3
        save(out / 'config.json', cfg)
        save(out / 'inventory.json', hosts)
        manifest = dict(protocol=protocol, n=n, epochs=epochs, repetition=1, seed=1, status='preparing', resources=dict(cpu_cores_per_node=2, memory_mib_per_node=4096, native_ec2=True), measurement=dict(start_output_count=100, end_output_count=epochs, intervals=epochs - 100, scope=f'output-100-to-output-{epochs}'), network=dict(profile='native-aws-eight-region', netem=False, regions=inventory['regions']), runtime_policy=dict(gomaxprocs=procs, crypto_workers=2, crypto_parallelism=2, go_memory_limit='2800MiB'), source=read(root / 'payload-manifest.json'), controller_version=self.version, started_at=utc())
        save(out / 'manifest.json', manifest)
        save(root / 'status.json', dict(state='running', phase='cell', cell=cell, outputs=epochs, updated_at=utc(), pid=os.getpid()))
        emit('cell-start', cell=cell, n=n, protocol=protocol, outputs=epochs)
        if protocol == 'grandline':
            p = run([root / 'payload/bin/grandline', '-config', out / 'config.json', '-write-setup', out / 'setup.json'], timeout=3600)
            (out / 'setup.log').write_text(p.stdout + p.stderr)

        def deploy(item):
            (i, h) = item
            folder = base + '/' + cell + f'/node{i}'
            unit = 'tyche-' + hashlib.sha256((inventory['campaign'] + cell + str(i) + self.version).encode()).hexdigest()[:24]
            ssh.call(h, 'mkdir -p ' + shlex.quote(folder) + '; test ! -e ' + shlex.quote(folder + '/node.exit'))
            ssh.put(h, out / 'config.json', folder + '/config.json')
            if protocol == 'grandline':
                ssh.put(h, out / 'setup.json', folder + '/setup.json')
            script = out / f'node{i}.launch.sh'
            script.write_text(worker_launcher(base, cell, i, protocol, epochs, unit, procs))
            ssh.put(h, script, folder + '/run.sh')
            cmd = shlex.join(['sudo', 'systemd-run', '--unit=' + unit, '--property=CPUAccounting=yes', '--property=MemoryAccounting=yes', '--property=CPUQuota=200%', '--property=TasksMax=infinity', '--property=RuntimeMaxSec=10800', '--property=KillMode=control-group', '--working-directory=' + folder, '/usr/bin/unshare', '--mount', '/bin/bash', folder + '/run.sh'])
            previous = ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip()
            if previous == 'not-found':
                launched = ssh.call(h, cmd, check=False)
                state = ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip()
                if state == 'not-found':
                    raise RuntimeError('native unit launch failed: ' + launched.stderr[-500:])
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                flag = ssh.call(h, f'p={shlex.quote(folder)}; if test -f $p/ready; then echo ready; elif test -f $p/node.exit; then echo failed; else echo waiting; fi').stdout.strip()
                if flag == 'ready':
                    break
                if flag == 'failed':
                    journal = ssh.call(h, 'sudo journalctl -u ' + unit + ' --no-pager -n 30', check=False).stdout
                    (out / f'node{i}.startup-failure.log').write_text(journal)
                    raise RuntimeError('native cgroup namespace failed')
                time.sleep(1)
            else:
                raise RuntimeError('native namespace readiness timeout')
            return dict(h, unit=unit, folder=folder)
        active = [dict(h, unit='tyche-' + hashlib.sha256((inventory['campaign'] + cell + str(i) + self.version).encode()).hexdigest()[:24], folder=base + '/' + cell + f'/node{i}') for (i, h) in enumerate(hosts)]
        try:
            active = parallel(deploy, list(enumerate(hosts)))
            save(out / 'units.json', active)
            parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/start')), active)
            manifest.update(status='running', protocol_released_at=utc())
            save(out / 'manifest.json', manifest)
            deadline = time.monotonic() + 10800
            released = False
            while time.monotonic() < deadline:

                def markers(h):
                    cmd = f"p={shlex.quote(h['folder'])}; if test -f $p/node.exit; then echo exit:$(cat $p/node.exit); elif test -f $p/benchmark-complete; then echo complete; elif test -f $p/generation-complete; then echo measured; else echo running; fi"
                    return ssh.call(h, cmd).stdout.strip()
                flags = parallel(markers, active)
                if any((flag.startswith('exit:') and flag != 'exit:0' for flag in flags)):
                    raise RuntimeError('node exited with error: ' + str(flags))
                if not released and all((flag in ('measured', 'complete', 'exit:0') for flag in flags)):
                    save(out / 'generation-barrier.json', dict(all_nodes_measured=True, checked_at=utc()))
                    parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/verify-start')), active)
                    released = True
                if all((flag == 'exit:0' for flag in flags)):
                    break
                save(root / 'status.json', dict(state='running', phase='verification' if released else 'generation', cell=cell, nodes_measured=sum((flag in ('measured', 'complete', 'exit:0') for flag in flags)), nodes=n, updated_at=utc(), pid=os.getpid()))
                time.sleep(10)
            else:
                raise RuntimeError('cell deadline exceeded')
            manifest['status'] = 'complete'
            save(out / 'manifest.json', manifest)
            self.collect_nodes(root, out, active, ssh)
            logs = [(out / f'node{i}/stdout.log').read_text() for i in range(n)]
            validation = measured.validate(logs, n, epochs, protocol)
            assert validation['run_valid'], validation
            for i in range(n):
                assert re.search('(?m)^oom_kill 0$', (out / f'node{i}/memory.events').read_text())
            metrics = measured.generation_metrics(out, n, epochs)
            save(out / 'generation-metrics.json', metrics)
            save(out / 'validation.json', validation)
            emit('cell-valid', cell=cell, throughput=statistics.mean((x['throughput_outputs_per_second'] for x in metrics['nodes'])))
        except BaseException:
            save(out / 'failure.json', dict(at=utc(), traceback=traceback.format_exc()))
            parallel(lambda h: ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False), active)
            try:
                self.collect_nodes(root, out, active, ssh)
            except Exception:
                pass
            raise
        finally:
            parallel(lambda h: ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False), active)

    def remote_size(self, root, inventory):
        ssh = SSH(root, root / 'control-key')
        base = '/home/ubuntu/' + inventory['campaign']
        selected = remote_ready(root, inventory)
        parallel(lambda h: read_remote(ssh, h, 'python3 -c ' + shlex.quote(PROBE)), selected)
        save(root / f"inventory-n{inventory['n']}.json", selected)
        payload = root / 'protocol.tar.gz'
        manifest = read(root / 'payload-manifest.json')

        def upload(h):
            expected = manifest['source']['binaries_sha256']
            probe = 'from pathlib import Path; import hashlib,json; r=Path(' + repr(base + '/payload/bin') + '); expected=' + repr(expected) + '; print(json.dumps(all((r/name).is_file() and hashlib.sha256((r/name).read_bytes()).hexdigest()==want for name,want in expected.items())))'
            cached = ssh.call(h, 'python3 -c ' + shlex.quote(probe), check=False)
            if cached.returncode == 0 and json.loads(cached.stdout):
                return
            ssh.put(h, payload, base + '/protocol.tar.gz')
            code = 'import pathlib,hashlib,tarfile; p=pathlib.Path(' + repr(base) + "); a=p/'protocol.tar.gz'; assert hashlib.sha256(a.read_bytes()).hexdigest()==" + repr(manifest['payload_sha256']) + "; d=p/'payload'; d.mkdir(exist_ok=True); t=tarfile.open(a); assert all(m.isfile() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); t.extractall(d,filter='data')"
            code = code.replace("t.extractall(d,filter='data')", '[( (d/m.name).parent.mkdir(parents=True,exist_ok=True), (d/m.name).write_bytes(t.extractfile(m).read()) ) for m in t.getmembers()]')
            ssh.call(h, 'python3 -c ' + shlex.quote(code) + '; chmod +x ' + base + '/payload/bin/*')
        parallel(upload, selected)
        if inventory['n'] == 16 and (not (root / 'smoke-valid.json').exists()):
            for protocol in self.protocols:
                self.remote_cell(root, inventory, selected[:4], protocol, 110, True)
            save(root / 'smoke-valid.json', dict(valid=True, n=4, outputs=110, window='100-to-110', protocols=self.protocols))
        for protocol in self.protocols:
            self.remote_cell(root, inventory, selected, protocol)
        save(root / 'status.json', dict(state='size_complete', n=inventory['n'], updated_at=utc(), pid=os.getpid()))

    def prepare(self, args):
        import urllib.request
        root = Path(args.out).resolve()
        root.mkdir(parents=True, exist_ok=True)
        assert not (root / 'plan.json').exists(), 'do not overwrite a campaign plan'
        settings = Path(args.settings).resolve()
        cfg = read(settings)
        assert cfg['instances']['type'] == 't3a.medium' and len(cfg['instances']['regions']) == 8
        assert cfg.get('port', {}).get('p2p', 9000) == 9000
        campaign = args.campaign or 'tyche-aws-' + datetime.now(timezone.utc).strftime('%Y%m%d') + '-600'
        assert re.fullmatch('tyche-aws-[a-z0-9-]+', campaign)
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct.open('https://checkip.amazonaws.com', timeout=20) as response:
            controller_ip = response.read().decode().strip()
        import ipaddress
        ipaddress.IPv4Address(controller_ip)
        manifest = common.stage_payload(root, __file__, self.protocols, scenario=self.scenario)
        save(root / 'payload-manifest.json', manifest)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', campaign, '-f', root / 'control-key'])
        plan = dict(scenario=self.scenario, campaign=campaign, created_at=utc(), settings_path=str(settings), regions=cfg['instances']['regions'], instance_type=cfg['instances']['type'], volume_gb=cfg['instances'].get('volume_gb', 24), controller_ip=controller_ip, sizes=SIZES, protocols=self.protocols, repetitions=1, outputs=600, warmup_outputs=100, intervals=500, peak_instances=161, bastion_region='eu-west-1', network='native AWS, no Docker/netem', candidate_counts={str(n): counts(n, cfg['instances']['regions'], True) for n in SIZES}, ssh_credentials='user key local only; ephemeral campaign key on bastion; no AWS credentials on bastion')
        save(root / 'plan.json', plan)
        emit('prepared', campaign=campaign, formal_cells=15, peak_instances=161, source_archive_sha256=manifest['source_archive_sha256'])

    def audit_stage(self, root, n):
        stage = root / f'n{n}.tar'
        destination = root / 'evidence' / f'n{n}'
        assert sha(stage) == read(root / f'n{n}.receipt.json')['sha256']
        safe_extract(stage, destination)
        payload = read(root / 'payload-manifest.json')
        rows = []
        histories = 0
        for protocol in self.protocols:
            cell = destination / 'results' / f'{protocol}-n{n}-r1'
            manifest = read(cell / 'manifest.json')
            assert manifest['source'] == payload and manifest['epochs'] == 600 and (manifest['status'] == 'complete')
            assert manifest['measurement']['start_output_count'] == 100 and manifest['measurement']['intervals'] == 500
            logs = [(cell / f'node{i}/stdout.log').read_text(encoding='utf-8') for i in range(n)]
            assert measured.validate(logs, n, 600, protocol)['run_valid']
            assert read(cell / 'generation-barrier.json')['all_nodes_measured']
            for i in range(n):
                node = cell / f'node{i}'
                receipt = read(cell / f'node{i}.receipt.json')
                archive = cell / f'node{i}.tar.gz'
                assert sha(archive) == receipt['sha256']
                with tarfile.open(archive) as tar:
                    names = [m.name for m in tar.getmembers()]
                    assert len(set(names)) == len(names)
                    assert set(names) == set(receipt['files_sha256'])
                    for member in tar.getmembers():
                        assert member.isfile() and len(PurePosixPath(member.name).parts) == 1
                        digest = hashlib.sha256()
                        with tar.extractfile(member) as stream:
                            for chunk in iter(lambda : stream.read(2 ** 20), b''):
                                digest.update(chunk)
                        assert digest.hexdigest() == receipt['files_sha256'][member.name]
                    assert ('history.json' in names) == (protocol == 'asyrand')
                    histories += int(protocol == 'asyrand')
                assert (node / 'node.exit').read_text().strip() == '0'
                assert (node / 'benchmark-complete').is_file()
                (quota, period) = map(int, (node / 'cpu.max').read_text().split())
                assert quota == 2 * period
                assert re.search('(?m)^oom_kill 0$', (node / 'memory.events').read_text())
                events = [json.loads(s) for s in (node / 'measurement.jsonl').read_text().splitlines()]
                times = re.findall('(?m)^ts=(\\S+) [^\\n]*?epoch=\\d+', logs[i])
                assert len(times) == 600
                first = next((e for e in events if e['outputs'] == 100))
                last = events[-1]
                assert measured.timestamp(times[99]) <= measured.timestamp(first['time']) <= measured.timestamp(times[100])
                assert measured.timestamp(times[599]) <= measured.timestamp(last['time'])
                if protocol == 'asyrand':
                    assert all((e['extra']['consumer_priority_enabled'] and e['extra']['consumption_prefetch_enabled'] and ('bottleneck' not in e['extra']) for e in events))
            metrics = measured.generation_metrics(cell, n, 600)
            assert metrics == read(cell / 'generation-metrics.json')
            row = dict(protocol=protocol, n=n, repetitions=1, outputs=600, warmup=100, intervals=500)
            for key in ('throughput_outputs_per_second', 'sent_kib_per_beacon_per_node', 'cpu_utilization_percent', 'cpu_ms_per_beacon'):
                row[key] = statistics.mean((x[key] for x in metrics['nodes']))
            row['actual_cpu_cores'] = row['cpu_utilization_percent'] * 0.02
            row['outputs_per_cpu_second_per_node'] = 1000 / row['cpu_ms_per_beacon']
            rows.append(row)
        save(root / f'n{n}.local-audit.json', dict(valid=True, n=n, formal_cells=3, nodes=3 * n, histories=histories, stage_sha256=sha(stage), checked_at=utc(), rows=rows))
        return rows

    def summarize(self, root):
        rows = [row for n in SIZES for row in read(root / f'n{n}.local-audit.json')['rows']]
        assert len(rows) == 15 and read(root / 'cleanup-audit.json')['valid']
        with (root / 'summary.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        styles = {'spurt': ('#35a88a', '^', 'SPURT'), 'grandline': ('#df932b', 's', 'Grandline'), 'asyrand': ('#347dc1', 'o', 'AsyRand adaptive W')}
        metrics = (('throughput_outputs_per_second', 'throughput', 'Throughput (beacons/s)'), ('sent_kib_per_beacon_per_node', 'communication', 'Application Tx (KiB / beacon / node)'), ('cpu_utilization_percent', 'cpu', 'CPU utilization (% of 2-vCPU quota)'), ('outputs_per_cpu_second_per_node', 'cpu-efficiency', 'Outputs per measured CPU second / node'))
        for (key, name, label) in metrics:
            (fig, ax) = plt.subplots(figsize=(7, 4.8))
            for (protocol, (color, marker, title)) in styles.items():
                points = [r for r in rows if r['protocol'] == protocol]
                ax.plot([r['n'] for r in points], [r[key] for r in points], color=color, marker=marker, label=title, lw=2)
            ax.set(xticks=SIZES, xlabel='Committee size n', ylabel=label, ylim=(0, 105) if name == 'cpu' else (0, None))
            ax.set_title('Native AWS t3a.medium: 2 vCPU / 4 GiB', loc='left')
            ax.grid(axis='y', alpha=0.2)
            ax.legend(frameon=False)
            fig.text(0.13, 0.02, 'Eight regions; real AWS network; no Docker/netem. One fresh run per point.\n600 outputs; first 100 warmup; common completion 100-to-600 window (500 intervals).\nNode means; no replication SD or significance claim. Application Tx excludes self/TLS/TCP.', fontsize=7)
            fig.tight_layout(rect=(0, 0.13, 1, 1))
            for ext in ('png', 'pdf', 'svg'):
                fig.savefig(root / f'{name}.{ext}', dpi=180, bbox_inches='tight')
            plt.close(fig)
        lines = ['# AWS三协议实验：600输出，前100热身', '', '15/15正式样本，每点一次；n=16/31/61/91/121，SPURT/Grandline/AsyRand adaptive W。所有点均为本轮新运行，逐规模固定八区域轮转清单，三协议共用清单。', '', '原生t3a.medium（2 vCPU/4 GiB，24 GiB gp3），CPU credits unlimited。专用跳板机只负责分发、公共离线setup、SSH调度和采集，不参与协议；P2P使用实例间直接TCP与固定身份TLS认证，不通过跳板机转发。没有Docker、netem或额外swap。', '', '备用数依次24/24/32/32/40，跳板机占其中一台，最多161台。全部资源带本任务精确标签，完成后已回收，审计见cleanup-audit.json。', '', '每节点600输出。CPU、应用Tx和墙钟严格按完成100→600共同差分，分母500；CPU按2核配额归一化，另存实际用核及每CPU秒产出。各节点独立比率先取均值，每点只有一次运行，不提供重复实验SD或显著性结论。', '', 'Go3/worker2/P2/GOMEMLIMIT2800MiB；仅SPURT/Grandline n16沿用已验证Go2策略。AsyRand保持adaptive W2–8和消费端预计算/优先调度，不放宽证明、子群、门限、绑定、ABA/RBC或前驱后继屏障。所有节点先完成测量，再开始完整历史的新鲜公开验证。', '', '|n|协议|吞吐 beacon/s|应用Tx KiB/beacon/node|CPU %|实际核数|CPU ms/beacon/node|', '|---:|---|---:|---:|---:|---:|---:|']
        for r in rows:
            lines.append(f"|{r['n']}|{styles[r['protocol']][2]}|{r['throughput_outputs_per_second']:.4f}|{r['sent_kib_per_beacon_per_node']:.3f}|{r['cpu_utilization_percent']:.2f}|{r['actual_cpu_cores']:.3f}|{r['cpu_ms_per_beacon']:.3f}|")
        lines += ['', '共享云硬件、SMT和跨区域WAN会影响结果。T3a突发CPU的额度/余额/额外收费计数单独保存；CPU效率不是墙钟吞吐，也不能线性外推不同CPU预算。node0 profile含热身，只用于热点诊断。', '', 'n4三协议110输出为独立功能/计量冒烟，不计入15个正式样本。全部原始节点日志、计量及完整AsyRand历史在逐规模tar证据包内，归档和每节点/文件SHA已独立核验；SSH私钥和AWS凭据不在证据包。', '', '[汇总CSV](summary.csv) · [清理审计](cleanup-audit.json)']
        for (_, name, label) in metrics:
            lines += ['', f'![{label}]({name}.png)']
        (root / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        files = [p for p in root.iterdir() if p.is_file() and p.name not in ('control-key', 'control-key.pub', 'known_hosts') and (not p.name.endswith('.partial'))]
        save(root / 'delivery-manifest.json', dict(valid=True, formal_cells=15, formal_nodes=960, formal_histories=320, measured_window='completion100-to-completion600;500 intervals', files_sha256={p.name: sha(p) for p in files}))
        emit('analysis-complete', formal_cells=15, formal_nodes=960, formal_histories=320)


class SilentCampaign(Campaign):
    scenario = 'silent'
    version = 'native-silent1-v1'
    protocols = ('asyrand',)
    Fleet = SilentFleet

    def validate_honest(self, logs, committee_size, epochs):
        assert len(logs) == committee_size - 1
        result = measured.validate(logs, len(logs), epochs, 'asyrand')
        result.update(committee_size=committee_size, honest_nodes=committee_size - 1, silent_faults=1, silent_node=f'node{committee_size - 1}')
        return result

    def silence_probe(self, ssh, host, base):
        code = "import pathlib,json,subprocess,datetime\nbase=BASE\npids=[]\nfor p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):\n    try:\n        args=p.read_bytes().split(b'\\0')\n        if args and args[0].decode(errors='replace')==base+'/payload/bin/asyrand':pids.append(int(p.parent.name))\n    except (OSError,PermissionError):pass\nports=subprocess.check_output(['ss','-H','-ltn','sport','=',':9000'],text=True).strip()\nprint(json.dumps(dict(valid=not pids and not ports,protocol_pids=pids,listening_9000=bool(ports),checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat())))\n".replace('BASE', repr(base))
        result = read_remote(ssh, host, 'python3 -c ' + shlex.quote(code))
        result.update(instance_id=host['id'], node=f"node{host['node']}", model='protocol process never started; OS and SSH online')
        assert result['valid'], result
        return result

    def remote_cell(self, root, inventory, hosts, protocol, epochs=600, smoke=False):
        n = len(hosts)
        cell = ('smoke-' if smoke else '') + f'{protocol}-n{n}-r1'
        assert protocol == 'asyrand' and n >= 4
        honest = n - 1
        start_count = 200
        assert epochs > start_count
        out = root / 'results' / cell
        if (out / 'validation.json').exists():
            assert read(out / 'validation.json')['run_valid']
            return
        if out.exists():
            raise RuntimeError('preserve incomplete cell; explicit reconciliation needed: ' + cell)
        out.mkdir(parents=True)
        ssh = SSH(root, root / 'control-key')
        base = '/home/ubuntu/' + inventory['campaign']
        cfg = native_config(protocol, n, epochs, hosts, inventory['campaign'])
        save(out / 'silent-before.json', self.silence_probe(ssh, hosts[-1], base))
        procs = 2 if protocol in ('spurt', 'grandline') and n == 16 else 3
        save(out / 'config.json', cfg)
        save(out / 'inventory.json', hosts)
        manifest = dict(protocol=protocol, n=n, epochs=epochs, repetition=1, seed=1, status='preparing', resources=dict(cpu_cores_per_node=2, memory_mib_per_node=4096, native_ec2=True), fault_model=dict(silent_faults=1, silent_node=f'node{n - 1}', honest_nodes=honest, committee_size=n, fault_budget=cfg['f'], injection='last committee member protocol process never started'), measurement=dict(start_output_count=start_count, end_output_count=epochs, intervals=epochs - start_count, scope=f'output-{start_count}-to-output-{epochs}'), network=dict(profile='native-aws-eight-region', netem=False, regions=inventory['regions']), runtime_policy=dict(gomaxprocs=procs, crypto_workers=2, crypto_parallelism=2, go_memory_limit='2800MiB'), source=read(root / 'payload-manifest.json'), controller_version=self.version, started_at=utc())
        save(out / 'manifest.json', manifest)
        save(root / 'status.json', dict(state='running', phase='cell', cell=cell, outputs=epochs, updated_at=utc(), pid=os.getpid()))
        emit('cell-start', cell=cell, n=n, protocol=protocol, outputs=epochs)
        if protocol == 'grandline':
            p = run([root / 'payload/bin/grandline', '-config', out / 'config.json', '-write-setup', out / 'setup.json'], timeout=3600)
            (out / 'setup.log').write_text(p.stdout + p.stderr)

        def deploy(item):
            (i, h) = item
            folder = base + '/' + cell + f'/node{i}'
            unit = 'tyche-' + hashlib.sha256((inventory['campaign'] + cell + str(i) + self.version).encode()).hexdigest()[:24]
            ssh.call(h, 'mkdir -p ' + shlex.quote(folder) + '; test ! -e ' + shlex.quote(folder + '/node.exit'))
            ssh.put(h, out / 'config.json', folder + '/config.json')
            if protocol == 'grandline':
                ssh.put(h, out / 'setup.json', folder + '/setup.json')
            script = out / f'node{i}.launch.sh'
            script.write_text(worker_launcher(base, cell, i, protocol, epochs, unit, procs))
            ssh.put(h, script, folder + '/run.sh')
            cmd = shlex.join(['sudo', 'systemd-run', '--unit=' + unit, '--property=CPUAccounting=yes', '--property=MemoryAccounting=yes', '--property=CPUQuota=200%', '--property=TasksMax=infinity', '--property=RuntimeMaxSec=10800', '--property=KillMode=control-group', '--working-directory=' + folder, '/usr/bin/unshare', '--mount', '/bin/bash', folder + '/run.sh'])
            previous = ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip()
            if previous == 'not-found':
                launched = ssh.call(h, cmd, check=False)
                state = ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip()
                if state == 'not-found':
                    raise RuntimeError('native unit launch failed: ' + launched.stderr[-500:])
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                flag = ssh.call(h, f'p={shlex.quote(folder)}; if test -f $p/ready; then echo ready; elif test -f $p/node.exit; then echo failed; else echo waiting; fi').stdout.strip()
                if flag == 'ready':
                    break
                if flag == 'failed':
                    journal = ssh.call(h, 'sudo journalctl -u ' + unit + ' --no-pager -n 30', check=False).stdout
                    (out / f'node{i}.startup-failure.log').write_text(journal)
                    raise RuntimeError('native cgroup namespace failed')
                time.sleep(1)
            else:
                raise RuntimeError('native namespace readiness timeout')
            return dict(h, unit=unit, folder=folder)
        active = [dict(h, unit='tyche-' + hashlib.sha256((inventory['campaign'] + cell + str(i) + self.version).encode()).hexdigest()[:24], folder=base + '/' + cell + f'/node{i}') for (i, h) in enumerate(hosts[:-1])]
        try:
            active = parallel(deploy, list(enumerate(hosts[:-1])))
            assert len(active) == honest and hosts[-1]['id'] not in {h['id'] for h in active}
            save(out / 'units.json', active)
            parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/start')), active)
            manifest.update(status='running', protocol_released_at=utc())
            save(out / 'manifest.json', manifest)
            deadline = time.monotonic() + 10800
            released = False
            while time.monotonic() < deadline:

                def markers(h):
                    cmd = f"p={shlex.quote(h['folder'])}; if test -f $p/node.exit; then echo exit:$(cat $p/node.exit); elif test -f $p/benchmark-complete; then echo complete; elif test -f $p/generation-complete; then echo measured; else echo running; fi"
                    return ssh.call(h, cmd).stdout.strip()
                flags = parallel(markers, active)
                if any((flag.startswith('exit:') and flag != 'exit:0' for flag in flags)):
                    raise RuntimeError('node exited with error: ' + str(flags))
                if not released and all((flag in ('measured', 'complete', 'exit:0') for flag in flags)):
                    save(out / 'generation-barrier.json', dict(all_nodes_measured=True, all_honest_nodes_measured=True, honest_nodes=honest, silent_faults=1, checked_at=utc()))
                    parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/verify-start')), active)
                    released = True
                if all((flag == 'exit:0' for flag in flags)):
                    break
                save(root / 'status.json', dict(state='running', phase='verification' if released else 'generation', cell=cell, nodes_measured=sum((flag in ('measured', 'complete', 'exit:0') for flag in flags)), nodes=honest, committee_size=n, silent_faults=1, updated_at=utc(), pid=os.getpid()))
                time.sleep(10)
            else:
                raise RuntimeError('cell deadline exceeded')
            manifest['status'] = 'complete'
            save(out / 'manifest.json', manifest)
            save(out / 'silent-after.json', self.silence_probe(ssh, hosts[-1], base))
            self.collect_nodes(root, out, active, ssh)
            logs = [(out / f'node{i}/stdout.log').read_text() for i in range(honest)]
            validation = self.validate_honest(logs, n, epochs)
            assert validation['run_valid'], validation
            for i in range(honest):
                assert re.search('(?m)^oom_kill 0$', (out / f'node{i}/memory.events').read_text())
            metrics = measured.generation_metrics(out, honest, epochs)
            save(out / 'generation-metrics.json', metrics)
            save(out / 'validation.json', validation)
            emit('cell-valid', cell=cell, throughput=statistics.mean((x['throughput_outputs_per_second'] for x in metrics['nodes'])))
        except BaseException:
            save(out / 'failure.json', dict(at=utc(), traceback=traceback.format_exc()))
            parallel(lambda h: ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False), active)
            try:
                self.collect_nodes(root, out, active, ssh)
            except Exception:
                pass
            raise
        finally:
            parallel(lambda h: ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False), active)

    def remote_size(self, root, inventory):
        ssh = SSH(root, root / 'control-key')
        base = '/home/ubuntu/' + inventory['campaign']
        selected = remote_ready(root, inventory)
        parallel(lambda h: read_remote(ssh, h, 'python3 -c ' + shlex.quote(PROBE)), selected)
        save(root / f"inventory-n{inventory['n']}.json", selected)
        payload = root / 'protocol.tar.gz'
        manifest = read(root / 'payload-manifest.json')

        def upload(h):
            expected = manifest['deployed_binaries_sha256']
            probe = 'from pathlib import Path; import hashlib,json; r=Path(' + repr(base + '/payload/bin') + '); expected=' + repr(expected) + '; print(json.dumps(all((r/name).is_file() and hashlib.sha256((r/name).read_bytes()).hexdigest()==want for name,want in expected.items())))'
            cached = ssh.call(h, 'python3 -c ' + shlex.quote(probe), check=False)
            if cached.returncode == 0 and json.loads(cached.stdout):
                return
            ssh.put(h, payload, base + '/protocol.tar.gz')
            code = 'import pathlib,hashlib,tarfile; p=pathlib.Path(' + repr(base) + "); a=p/'protocol.tar.gz'; assert hashlib.sha256(a.read_bytes()).hexdigest()==" + repr(manifest['payload_sha256']) + "; d=p/'payload'; d.mkdir(exist_ok=True); t=tarfile.open(a); assert all(m.isfile() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); t.extractall(d,filter='data')"
            code = code.replace("t.extractall(d,filter='data')", '[( (d/m.name).parent.mkdir(parents=True,exist_ok=True), (d/m.name).write_bytes(t.extractfile(m).read()) ) for m in t.getmembers()]')
            ssh.call(h, 'python3 -c ' + shlex.quote(code) + '; chmod +x ' + base + '/payload/bin/*')
        parallel(upload, selected)
        if inventory['n'] == 16 and (not (root / 'smoke-valid.json').exists()):
            for protocol in self.protocols:
                self.remote_cell(root, inventory, selected[:4], protocol, 240, True)
            save(root / 'smoke-valid.json', dict(valid=True, n=4, honest_nodes=3, silent_faults=1, outputs=240, window='200-to-240', protocols=self.protocols))
        for protocol in self.protocols:
            self.remote_cell(root, inventory, selected, protocol)
        save(root / 'status.json', dict(state='size_complete', n=inventory['n'], updated_at=utc(), pid=os.getpid()))

    def prepare(self, args):
        import urllib.request
        root = Path(args.out).resolve()
        root.mkdir(parents=True, exist_ok=True)
        assert not (root / 'plan.json').exists(), 'do not overwrite a campaign plan'
        settings = Path(args.settings).resolve()
        cfg = read(settings)
        assert cfg['instances']['type'] == 't3a.medium' and len(cfg['instances']['regions']) == 8
        assert cfg.get('port', {}).get('p2p', 9000) == 9000
        campaign = args.campaign or 'tyche-aws-silent1-' + datetime.now(timezone.utc).strftime('%Y%m%d') + '-600'
        assert re.fullmatch('tyche-aws-[a-z0-9-]+', campaign)
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct.open('https://checkip.amazonaws.com', timeout=20) as response:
            controller_ip = response.read().decode().strip()
        import ipaddress
        ipaddress.IPv4Address(controller_ip)
        manifest = common.stage_payload(root, __file__, self.protocols, scenario=self.scenario)
        save(root / 'payload-manifest.json', manifest)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', campaign, '-f', root / 'control-key'])
        plan = dict(scenario=self.scenario, campaign=campaign, created_at=utc(), settings_path=str(settings), regions=cfg['instances']['regions'], instance_type=cfg['instances']['type'], volume_gb=cfg['instances'].get('volume_gb', 24), controller_ip=controller_ip, sizes=SIZES, protocols=self.protocols, repetitions=1, outputs=600, warmup_outputs=200, intervals=400, silent_faults=1, silent_node_policy='node(n-1), protocol process never started; committee membership and f unchanged', reference_summary_path=str(REPO / 'benchmark/runs/aws-20261027-600/last400/summary.csv'), peak_instances=161, bastion_region='eu-west-1', network='native AWS, no Docker/netem', candidate_counts={str(n): counts(n, cfg['instances']['regions'], True) for n in SIZES}, ssh_credentials='user key local only; ephemeral campaign key on bastion; no AWS credentials on bastion')
        save(root / 'plan.json', plan)
        emit('prepared', campaign=campaign, formal_cells=5, formal_honest_nodes=315, silent_faults=1, peak_instances=161, source_archive_sha256=manifest['source_archive_sha256'])

    def audit_stage(self, root, n):
        stage = root / f'n{n}.tar'
        destination = root / 'evidence' / f'n{n}'
        assert sha(stage) == read(root / f'n{n}.receipt.json')['sha256']
        safe_extract(stage, destination)
        payload = read(root / 'payload-manifest.json')
        rows = []
        histories = 0
        for protocol in self.protocols:
            cell = destination / 'results' / f'{protocol}-n{n}-r1'
            manifest = read(cell / 'manifest.json')
            assert manifest['source'] == payload and manifest['epochs'] == 600 and (manifest['status'] == 'complete')
            assert manifest['measurement']['start_output_count'] == 200 and manifest['measurement']['intervals'] == 400
            assert manifest['fault_model']['silent_faults'] == 1 and manifest['fault_model']['silent_node'] == f'node{n - 1}'
            assert manifest['fault_model']['honest_nodes'] == n - 1 and manifest['fault_model']['fault_budget'] == (n - 1) // 3
            assert len(read(cell / 'config.json')['cluster_index']) == n
            assert len(read(cell / 'units.json')) == n - 1 and (not (cell / f'node{n - 1}').exists())
            assert read(cell / 'silent-before.json')['valid'] and read(cell / 'silent-after.json')['valid']
            logs = [(cell / f'node{i}/stdout.log').read_text(encoding='utf-8') for i in range(n - 1)]
            assert self.validate_honest(logs, n, 600)['run_valid']
            assert read(cell / 'generation-barrier.json')['all_nodes_measured']
            for i in range(n - 1):
                node = cell / f'node{i}'
                receipt = read(cell / f'node{i}.receipt.json')
                archive = cell / f'node{i}.tar.gz'
                assert sha(archive) == receipt['sha256']
                with tarfile.open(archive) as tar:
                    names = [m.name for m in tar.getmembers()]
                    assert len(set(names)) == len(names)
                    assert set(names) == set(receipt['files_sha256'])
                    for member in tar.getmembers():
                        assert member.isfile() and len(PurePosixPath(member.name).parts) == 1
                        digest = hashlib.sha256()
                        with tar.extractfile(member) as stream:
                            for chunk in iter(lambda : stream.read(2 ** 20), b''):
                                digest.update(chunk)
                        assert digest.hexdigest() == receipt['files_sha256'][member.name]
                    assert ('history.json' in names) == (protocol == 'asyrand')
                    histories += int(protocol == 'asyrand')
                assert (node / 'node.exit').read_text().strip() == '0'
                assert (node / 'benchmark-complete').is_file()
                (quota, period) = map(int, (node / 'cpu.max').read_text().split())
                assert quota == 2 * period
                assert re.search('(?m)^oom_kill 0$', (node / 'memory.events').read_text())
                events = [json.loads(s) for s in (node / 'measurement.jsonl').read_text().splitlines()]
                times = re.findall('(?m)^ts=(\\S+) [^\\n]*?epoch=\\d+', logs[i])
                assert len(times) == 600
                first = next((e for e in events if e['outputs'] == 200))
                last = events[-1]
                assert measured.timestamp(times[199]) <= measured.timestamp(first['time']) <= measured.timestamp(times[200])
                assert measured.timestamp(times[599]) <= measured.timestamp(last['time'])
                if protocol == 'asyrand':
                    assert all((e['extra']['consumer_priority_enabled'] and e['extra']['consumption_prefetch_enabled'] and ('bottleneck' not in e['extra']) for e in events))
            metrics = measured.generation_metrics(cell, n - 1, 600)
            assert metrics == read(cell / 'generation-metrics.json')
            row = dict(protocol=protocol, n=n, honest_nodes=n - 1, silent_faults=1, repetitions=1, outputs=600, warmup=200, intervals=400)
            for key in ('throughput_outputs_per_second', 'sent_kib_per_beacon_per_node', 'cpu_utilization_percent', 'cpu_ms_per_beacon'):
                row[key] = statistics.mean((x[key] for x in metrics['nodes']))
            row['actual_cpu_cores'] = row['cpu_utilization_percent'] * 0.02
            row['outputs_per_cpu_second_per_node'] = 1000 / row['cpu_ms_per_beacon']
            rows.append(row)
        save(root / f'n{n}.local-audit.json', dict(valid=True, n=n, formal_cells=1, nodes=n - 1, histories=histories, stage_sha256=sha(stage), checked_at=utc(), rows=rows))
        if n == 16:
            smoke = destination / 'results/smoke-asyrand-n4-r1'
            assert read(smoke / 'manifest.json')['fault_model']['silent_node'] == 'node3'
            assert read(smoke / 'silent-before.json')['valid'] and read(smoke / 'silent-after.json')['valid']
            assert self.validate_honest([(smoke / f'node{i}/stdout.log').read_text() for i in range(3)], 4, 240)['run_valid']
            assert measured.generation_metrics(smoke, 3, 240) == read(smoke / 'generation-metrics.json')
            for i in range(3):
                archive = smoke / f'node{i}.tar.gz'
                receipt = read(smoke / f'node{i}.receipt.json')
                assert sha(archive) == receipt['sha256']
                with tarfile.open(archive) as tar:
                    assert {m.name for m in tar.getmembers()} == set(receipt['files_sha256'])
                    for member in tar:
                        assert member.isfile() and len(PurePosixPath(member.name).parts) == 1
                        digest = hashlib.sha256()
                        with tar.extractfile(member) as stream:
                            for chunk in iter(lambda : stream.read(2 ** 20), b''):
                                digest.update(chunk)
                        assert digest.hexdigest() == receipt['files_sha256'][member.name]
                assert 'history.json' in receipt['files_sha256']
            save(root / 'smoke.local-audit.json', dict(valid=True, committee_size=4, silent_faults=1, honest_nodes=3, histories=3, outputs=240, window='200-to240/40', checked_at=utc()))
        return rows

    def summarize(self, root):
        rows = [row for n in SIZES for row in read(root / f'n{n}.local-audit.json')['rows']]
        assert len(rows) == 5 and read(root / 'cleanup-audit.json')['valid']
        assert all((row['silent_faults'] == 1 and row['honest_nodes'] == row['n'] - 1 and (row['warmup'] == 200) and (row['intervals'] == 400) for row in rows))
        with (root / 'summary.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        baseline = list(csv.DictReader(Path(read(root / 'plan.json')['reference_summary_path']).open(encoding='utf-8', newline='')))
        baseline = [dict(row, n=int(row['n'])) for row in baseline if row['protocol'] == 'asyrand']
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        plt.rcParams.update({'pdf.fonttype': 42, 'svg.fonttype': 'none'})
        metrics = (('throughput_outputs_per_second', 'throughput', 'Throughput (beacons/s)'), ('sent_kib_per_beacon_per_node', 'communication', 'Application Tx (KiB / beacon / honest node)'), ('cpu_utilization_percent', 'cpu', 'CPU utilization (% of 2-vCPU quota)'))

        def panel(ax, key, label):
            ax.plot(SIZES, [float(row[key]) for row in baseline], color='#347dc1', marker='o', label='AsyRand, no injected fault (reference)', lw=2)
            ax.plot(SIZES, [row[key] for row in rows], color='#9659b3', marker='D', label='AsyRand, one silent member', lw=2)
            ax.set(xticks=SIZES, xlabel='Committee size n', ylabel=label, ylim=(0, 105) if key == 'cpu_utilization_percent' else (0, None))
            ax.grid(axis='y', alpha=0.2)
        caption = '600 outputs; first 200 warmup; completion 200-to-600 (400 intervals). One run per point.\nMeans over n-1 honest nodes; silent node(n-1) remains a member, never starts the protocol.\nNative AWS 2 vCPU / 4 GiB; references come from a separate no-fault campaign.'
        for (key, name, label) in metrics:
            (fig, ax) = plt.subplots(figsize=(7.6, 5.1))
            panel(ax, key, label)
            ax.legend(frameon=False, fontsize=8.5)
            ax.set_title('AsyRand adaptive W: silent fault = 1', loc='left')
            fig.text(0.13, 0.02, caption, fontsize=7)
            fig.tight_layout(rect=(0, 0.14, 1, 1))
            for ext in ('png', 'pdf', 'svg'):
                fig.savefig(root / f'{name}.{ext}', dpi=250, bbox_inches='tight')
            plt.close(fig)
        (fig, axes) = plt.subplots(1, 3, figsize=(16, 5))
        for (ax, (key, name, label)) in zip(axes, metrics):
            panel(ax, key, label)
        (handles, labels) = axes[0].get_legend_handles_labels()
        fig.legend(handles, labels, loc='upper center', ncol=2, frameon=False)
        fig.text(0.06, 0.015, caption, fontsize=8)
        fig.tight_layout(rect=(0, 0.17, 1, 0.91))
        for ext in ('png', 'pdf', 'svg'):
            fig.savefig(root / f'combined.{ext}', dpi=250, bbox_inches='tight')
        plt.close(fig)
        lines = ['# AsyRand AWS silent fault = 1', '', '五个规模n16/31/61/91/121，各一次新运行。完整n人成员名单、f=(n-1)/3及所有门限不变，固定最后成员node(n-1)不启动协议进程；只对n-1个诚实节点计量并要求其一致输出和完整历史新鲜验证。', '', '每节点600输出，前200热身；完成200到600共同差分，分母400。CPU按2-vCPU配额归一化，应用Tx排除自投递和TLS/TCP。315份正式日志和315份完整历史；n4三诚实一静默240输出冒烟另列。', '', '原生t3a.medium 2vCPU/4GiB/24GiB gp3，credits unlimited；真实八区域WAN，无Docker/netem/swap。Go3/worker2/P2/2800MiB，adaptive W2-8及消费优化、安全与验证屏障不改。备用仅资格筛选，固定清单后立即回收。结束后精确清理本任务实例/卷/SG。', '', '无故障参考来自之前独立campaign的同200到600窗口，运行时间和实例不同，不能作为严格配对因果实验。每点单次，无重复SD/显著性或稳态保证；共享SMT和T3a credits可能影响表现。CPU效率定义为1000/节点平均CPU毫秒每beacon。', '', '|n|诚实节点|静默节点|吞吐 beacon/s|应用Tx KiB/beacon/honest node|CPU %|CPU ms/beacon/honest node|', '|---:|---:|---|---:|---:|---:|---:|']
        for row in rows:
            lines.append(f"|{row['n']}|{row['honest_nodes']}|node{row['n'] - 1}|{row['throughput_outputs_per_second']:.4f}|{row['sent_kib_per_beacon_per_node']:.3f}|{row['cpu_utilization_percent']:.2f}|{row['cpu_ms_per_beacon']:.3f}|")
        lines += ['', '![三图合一](combined.png)', '', '原始节点归档包含完整历史，逐文件SHA、诚实节点输出一致、完整历史新鲜验证及静默节点启动前后无进程/9000监听证据均独立校验。SSH私钥和AWS凭据不入交付。']
        (root / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        files = [p for p in root.iterdir() if p.is_file() and p.name not in ('control-key', 'control-key.pub', 'known_hosts', 'delivery-manifest.json') and ('.private.' not in p.name) and (not p.name.endswith('.partial'))]
        save(root / 'delivery-manifest.json', dict(valid=True, formal_cells=5, formal_nodes=315, formal_histories=315, silent_faults=1, measured_window='completion200-to-completion600;400 intervals', files_sha256={p.name: sha(p) for p in files}))
        emit('analysis-complete', formal_cells=5, formal_nodes=315, formal_histories=315)


class RepeatCampaign(Campaign):
    scenario = 'repeat'
    version = 'native-repeat23-compact-v2'
    repetitions = (2, 3)
    Fleet = RepeatFleet

    def collect_nodes(self, root, out, active, ssh, protocol, repetition, epochs):

        def one(h):
            command = shlex.join(['sudo', 'python3', f"/home/ubuntu/{read(root / 'plan.json')['campaign']}/payload/bench_results.py", '--folder', h['folder'], '--protocol', protocol, '--nodes', str(len(active)), '--repetition', str(repetition), '--epochs', str(epochs)])
            result = json.loads(ssh.call(h, command, timeout=180).stdout)
            compact.verify_result(result)
            save(out / f"node{h['node']}.json", result)
            return result
        results = parallel(one, active, 4)
        reference = results[0]['beacons_sha256']
        for result in results:
            compact.verify_result(result, reference)
        return results

    def remote_cell(self, root, inventory, hosts, protocol, repetition, epochs=600, smoke=False):
        n = len(hosts)
        cell = ('smoke-' if smoke else '') + f'{protocol}-n{n}-r{repetition}'
        out = root / 'results' / cell
        if (out / 'validation.json').exists():
            assert read(out / 'validation.json')['valid']
            return
        assert not out.exists(), 'preserve incomplete cell; explicit reconciliation required: ' + cell
        out.mkdir(parents=True)
        ssh = common.SSH(root, root / 'control-key')
        remote = '/home/ubuntu/' + inventory['campaign']
        config = native_config(protocol, n, epochs, hosts, inventory['campaign'], repetition)
        save(out / 'config.json', config)
        procs = 2 if protocol in ('spurt', 'grandline') and n == 16 else 3
        manifest = dict(protocol=protocol, n=n, repetition=repetition, epochs=epochs, status='preparing', faults_injected=0, fault_budget=(n - 1) // 3, measurement=dict(start_output_count=200, end_output_count=epochs, intervals=epochs - 200), resources=dict(cpu_cores_per_node=2, memory_mib_per_node=4096, native_ec2=True), runtime_policy=dict(gomaxprocs=procs, crypto_workers=2, crypto_parallelism=2, go_memory_limit='2800MiB'), source=read(root / 'payload-manifest.json'), controller_version=self.version, started_at=utc())
        save(out / 'manifest.json', manifest)
        emit('cell-start', cell=cell)
        if protocol == 'grandline':
            result = run([root / 'payload/bin/grandline', '-config', out / 'config.json', '-write-setup', out / 'setup.json'], timeout=3600)
            assert result.returncode == 0
        active = [dict(h, unit='tyche-' + hashlib.sha256((inventory['campaign'] + cell + str(i) + self.version).encode()).hexdigest()[:24], folder=remote + '/' + cell + f'/node{i}') for (i, h) in enumerate(hosts)]

        def deploy(h):
            folder = h['folder']
            unit = h['unit']
            i = h['node']
            ssh.call(h, 'mkdir -p ' + shlex.quote(folder) + '; test ! -e ' + shlex.quote(folder + '/node.exit'))
            ssh.put(h, out / 'config.json', folder + '/config.json')
            if protocol == 'grandline':
                ssh.put(h, out / 'setup.json', folder + '/setup.json')
            script = out / f'node{i}.launch.sh'
            script.write_text(worker_launcher(remote, cell, i, protocol, epochs, unit, procs))
            ssh.put(h, script, folder + '/run.sh')
            cmd = shlex.join(['sudo', 'systemd-run', '--unit=' + unit, '--property=CPUAccounting=yes', '--property=MemoryAccounting=yes', '--property=CPUQuota=200%', '--property=TasksMax=infinity', '--property=RuntimeMaxSec=10800', '--property=KillMode=control-group', '--working-directory=' + folder, '/usr/bin/unshare', '--mount', '/bin/bash', folder + '/run.sh'])
            if ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip() == 'not-found':
                launched = ssh.call(h, cmd, check=False)
                assert ssh.call(h, 'systemctl show ' + unit + ' -p LoadState --value').stdout.strip() != 'not-found', launched.stderr[-500:]
            until = time.monotonic() + 120
            while time.monotonic() < until:
                flag = ssh.call(h, f'p={shlex.quote(folder)}; if test -f $p/ready; then echo ready; elif test -f $p/node.exit; then echo failed; else echo waiting; fi').stdout.strip()
                if flag == 'ready':
                    return
                if flag == 'failed':
                    raise RuntimeError('native unit failed before readiness')
                time.sleep(1)
            raise RuntimeError('native unit readiness timeout')
        try:
            parallel(deploy, active)
            save(out / 'units.json', active)
            parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/start')), active)
            manifest.update(status='running', protocol_released_at=utc())
            save(out / 'manifest.json', manifest)
            deadline = time.monotonic() + 10800
            released = False
            while time.monotonic() < deadline:

                def marker(h):
                    return ssh.call(h, f"p={shlex.quote(h['folder'])}; if test -f $p/node.exit; then echo exit:$(cat $p/node.exit); elif test -f $p/benchmark-complete; then echo complete; elif test -f $p/generation-complete; then echo measured; else echo running; fi").stdout.strip()
                flags = parallel(marker, active)
                assert not any((v.startswith('exit:') and v != 'exit:0' for v in flags)), flags
                if not released and all((v in ('measured', 'complete', 'exit:0') for v in flags)):
                    save(out / 'generation-barrier.json', dict(all_nodes_measured=True, checked_at=utc()))
                    parallel(lambda h: ssh.call(h, 'touch ' + shlex.quote(h['folder'] + '/verify-start')), active)
                    released = True
                if all((v == 'exit:0' for v in flags)):
                    break
                save(root / 'status.json', dict(state='running', phase='verification' if released else 'generation', cell=cell, nodes_measured=sum((v in ('measured', 'complete', 'exit:0') for v in flags)), nodes=n, pid=os.getpid(), updated_at=utc()))
                time.sleep(10)
            else:
                raise RuntimeError('cell deadline exceeded')
            results = self.collect_nodes(root, out, active, ssh, protocol, repetition, epochs)
            manifest.update(status='complete', completed_at=utc())
            save(out / 'manifest.json', manifest)
            save(out / 'validation.json', dict(valid=True, nodes=n, outputs=epochs, beacons_sha256=results[0]['beacons_sha256'], full_history_fresh_verified=protocol == 'asyrand', checked_at=utc()))
            emit('cell-valid', cell=cell, throughput=statistics.mean((r['metrics']['throughput_outputs_per_second'] for r in results)))
        except BaseException:
            save(out / 'failure.json', dict(at=utc(), traceback=traceback.format_exc()))

            def diagnostic(h):
                ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False)
                p = ssh.call(h, 'sudo tail -c 65536 ' + shlex.quote(h['folder'] + '/stdout.log'), check=False)
                (out / f"node{h['node']}.failure.log").write_text(p.stdout + p.stderr)
            try:
                parallel(diagnostic, active, 4)
            except Exception:
                pass
            raise
        finally:
            parallel(lambda h: ssh.call(h, 'sudo systemctl stop ' + h['unit'], check=False), active)

    def bundle(self, root, n, failed=False):
        files = []
        for cell in sorted((root / 'results').glob('*')):
            if not cell.is_dir() or (n and f'-n{n}-' not in cell.name and (not (n == 16 and cell.name.startswith('smoke-')))):
                continue
            for path in sorted(cell.iterdir()):
                if path.name in ('config.json', 'manifest.json', 'generation-barrier.json', 'validation.json', 'units.json', 'failure.json') or re.fullmatch('node\\d+\\.json', path.name) or path.name.endswith('.failure.log'):
                    assert path.is_file() and (not path.is_symlink())
                    files.append(path)
        files += [p for p in (root / 'payload-manifest.json', root / f'inventory-n{n}.json') if p.exists()]
        total = sum((p.stat().st_size for p in files))
        assert total <= 64 * 2 ** 20, 'compact result budget exceeded; never fall back to full histories'
        output = root / f'n{n}.tar.gz'
        with tarfile.open(output, 'w:gz', compresslevel=6) as tar:
            for path in files:
                tar.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
        assert output.stat().st_size <= 16 * 2 ** 20
        cells = [read(p) for p in files if p.name == 'manifest.json']
        receipt = dict(valid=not failed, n=n, bytes=output.stat().st_size, sha256=sha(output), files=len(files), created_at=utc(), cells=[dict(protocol=m['protocol'], n=m['n'], repetition=m['repetition'], epochs=m['epochs'], status=m['status']) for m in cells], selected_instance_ids=[h['id'] for h in read(root / f'inventory-n{n}.json')] if (root / f'inventory-n{n}.json').exists() else [], files_sha256={p.relative_to(root).as_posix(): sha(p) for p in files}, raw_logs_and_histories_included=False)
        save(root / f'n{n}.receipt.json', receipt)
        return receipt

    def remote_size(self, root, inventory):
        ssh = common.SSH(root, root / 'control-key')
        remote = '/home/ubuntu/' + inventory['campaign']
        selected = common.remote_ready(root, inventory)
        save(root / f"inventory-n{inventory['n']}.json", selected)
        expected = read(root / 'payload-manifest.json')['deployed_binaries_sha256']

        def upload(h):
            ssh.put(h, root / 'protocol.tar.gz', remote + '/protocol.tar.gz')
            code = 'import pathlib,hashlib,tarfile; r=pathlib.Path(' + repr(remote) + "); a=r/'protocol.tar.gz'; assert hashlib.sha256(a.read_bytes()).hexdigest()==" + repr(sha(root / 'protocol.tar.gz')) + "; t=tarfile.open(a); assert all(m.isfile() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts for m in t); t=tarfile.open(a); [( (r/'payload'/m.name).parent.mkdir(parents=True,exist_ok=True),(r/'payload'/m.name).write_bytes(t.extractfile(m).read()) ) for m in t]"
            ssh.call(h, 'python3 -c ' + shlex.quote(code) + '; chmod +x ' + remote + '/payload/bin/*')
            probe = 'from pathlib import Path; import hashlib,json; r=Path(' + repr(remote + '/payload/bin') + '); e=' + repr(expected) + '; print(json.dumps(all(hashlib.sha256((r/k).read_bytes()).hexdigest()==v for k,v in e.items())))'
            assert json.loads(ssh.call(h, 'python3 -c ' + shlex.quote(probe)).stdout)
        parallel(upload, selected)
        if inventory['n'] == 16 and (not (root / 'smoke-valid.json').exists()):
            for protocol in self.protocols:
                self.remote_cell(root, inventory, selected[:4], protocol, 0, 240, True)
            save(root / 'smoke-valid.json', dict(valid=True, protocols=self.protocols, n=4, outputs=240, window='200-to-240/40'))
        for repetition in self.repetitions:
            for protocol in self.protocols:
                self.remote_cell(root, inventory, selected, protocol, repetition)
        save(root / 'status.json', dict(state='size_complete', n=inventory['n'], pid=os.getpid(), updated_at=utc()))
        receipt = self.bundle(root, inventory['n'])
        assert len([c for c in receipt['cells'] if c['epochs'] == 600]) == 6

    def prepare(self, args):
        root = Path(args.out).resolve()
        root.mkdir(parents=True, exist_ok=True)
        assert not (root / 'plan.json').exists()
        cfg = read(args.settings)
        assert cfg['instances']['type'] == 't3a.medium' and len(cfg['instances']['regions']) == 8
        campaign = args.campaign or 'tyche-aws-repeat23-20261028-600'
        assert re.fullmatch('tyche-aws-[a-z0-9-]+', campaign)
        manifest = common.stage_payload(root, __file__, self.protocols, compact=True, scenario=self.scenario)
        save(root / 'payload-manifest.json', manifest)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', campaign, '-f', root / 'control-key'])
        addresses = common.egress_addresses()
        save(root / 'plan.json', dict(scenario=self.scenario, campaign=campaign, created_at=utc(), settings_path=str(Path(args.settings).resolve()), regions=cfg['instances']['regions'], instance_type='t3a.medium', volume_gb=24, controller_ip=addresses[0], controller_addresses=addresses, sizes=SIZES, protocols=self.protocols, repetitions=self.repetitions, outputs=600, warmup_outputs=200, intervals=400, faults_injected=0, peak_instances=161, bastion_region='eu-west-1', worker_release='after bastion validation, before local download', baseline_summary_path=str(REPO / 'benchmark/runs/aws-20261027-600/last400/summary.csv'), baseline_nodes_path=str(root / 'baseline-r1/per-node.csv'), compact_results_only=True))
        emit('prepared', formal_cells=30, new_node_results=1920, campaign=campaign)

    def audit_stage(self, root, n):
        receipt = read(root / f'n{n}.receipt.json')
        archive = root / f'n{n}.tar.gz'
        assert receipt['valid'] and sha(archive) == receipt['sha256'] and (archive.stat().st_size == receipt['bytes'])
        assert not receipt['raw_logs_and_histories_included']
        destination = root / 'evidence' / f'n{n}'
        safe_extract(archive, destination)
        assert all((sha(destination / name) == want for (name, want) in receipt['files_sha256'].items()))
        rows = []
        node_rows = []
        smokes = 0
        for cell in sorted((destination / 'results').iterdir()):
            manifest = read(cell / 'manifest.json')
            size = manifest['n']
            epochs = manifest['epochs']
            assert manifest['status'] == 'complete' and manifest['faults_injected'] == 0
            assert manifest['source'] == read(root / 'payload-manifest.json')
            assert len(read(cell / 'config.json')['cluster_index']) == size and read(cell / 'config.json')['f'] == (size - 1) // 3
            assert read(cell / 'generation-barrier.json')['all_nodes_measured']
            assert read(cell / 'validation.json')['valid']
            results = [read(cell / f'node{i}.json') for i in range(size)]
            for (i, result) in enumerate(results):
                assert result['node'] == i and result['n'] == size and (result['protocol'] == manifest['protocol'])
                compact.verify_result(result, results[0]['beacons_sha256'])
            if epochs != 600:
                assert size == 4 and epochs == 240
                smokes += 1
                continue
            row = dict(protocol=manifest['protocol'], n=size, repetition=manifest['repetition'], faults_injected=0, outputs=600, warmup=200, intervals=400, nodes=size)
            for key in ('throughput_outputs_per_second', 'sent_kib_per_beacon_per_node', 'cpu_utilization_percent', 'cpu_ms_per_beacon', 'actual_cpu_cores'):
                row[key] = statistics.mean((r['metrics'][key] for r in results))
            row['outputs_per_cpu_second_per_node'] = 1000 / row['cpu_ms_per_beacon']
            rows.append(row)
            for result in results:
                node_rows.append(dict(protocol=row['protocol'], n=size, repetition=row['repetition'], node=result['node'], start_output_count=200, end_output_count=600, start_time=result['boundary_start']['time'], end_time=result['boundary_end']['time'], **result['metrics'], result_path=(cell / f"node{result['node']}.json").relative_to(root).as_posix()))
        assert {(r['protocol'], r['repetition']) for r in rows} == {(p, r) for p in self.protocols for r in self.repetitions}
        assert len(node_rows) == 6 * n
        assert smokes == (3 if n == 16 else 0)
        save(root / f'n{n}.local-audit.json', dict(valid=True, n=n, formal_cells=6, nodes=6 * n, smoke_cells=smokes, rows=rows, node_rows=node_rows, archive_sha256=receipt['sha256'], checked_at=utc()))
        return rows

    def verify_ready(self, receipt, n):
        assert receipt['valid'] and receipt['n'] == n and (not receipt['raw_logs_and_histories_included'])
        assert receipt['bytes'] <= 16 * 2 ** 20 and len(receipt['selected_instance_ids']) == n
        cells = [c for c in receipt['cells'] if c['epochs'] == 600]
        assert {(c['protocol'], c['repetition']) for c in cells} == {(p, r) for p in self.protocols for r in self.repetitions}
        assert all((c['n'] == n and c['status'] == 'complete' for c in cells))

    def collect_size(self, fleet, gateway, remote, n):
        receipt = json.loads(fleet.control(gateway, 'cat ' + shlex.quote(remote + f'/n{n}.receipt.json')).stdout)
        self.verify_ready(receipt, n)
        save(fleet.root / f'n{n}.receipt.json', receipt)
        fleet.release_workers(n, gateway)
        fleet.download(gateway, remote, n, receipt)
        self.audit_stage(fleet.root, n)

    def wait_bastion(self, fleet, gateway):
        for attempt in range(20):
            try:
                result = fleet.control(gateway, 'cloud-init status --wait >/dev/null; uname -r', timeout=90, check=False)
                if result.returncode == 0:
                    return
            except (OSError, common.subprocess.TimeoutExpired):
                pass
            except RuntimeError as error:
                if 'management SSH unavailable' not in str(error):
                    raise
            time.sleep(8)
        raise RuntimeError('bastion SSH unavailable after bounded boot retries')

    def acquire_bastion(self, fleet, resume):
        rows = fleet.refresh()
        if rows:
            assert resume and len(rows) == 1 and (rows[0]['role'] == 'bastion') and (rows[0]['state'] == 'running'), 'explicitly reconcile live workers before restarting'
            expected = fleet.data['bastion']
            assert rows[0]['id'] == expected['id']
            return fleet.authorize(fleet.plan['controller_ip'])
        if resume:
            fleet.data['groups'] = {}
            fleet.persist()
        fleet.launch(fleet.plan['bastion_region'], 1, 'bastion')
        fleet.wait_running({fleet.plan['bastion_region']: 1})
        return fleet.authorize(fleet.plan['controller_ip'])

    def preserve_failure_bundle(self, fleet, gateway, remote, n):
        if n == 0:
            return False
        try:
            fleet.control(gateway, shlex.join(['python3', remote + '/aws_bench.py', 'bundle', '--scenario', 'repeat', '--out', remote, '--nodes', str(n)]), timeout=120)
            receipt = json.loads(fleet.control(gateway, 'cat ' + remote + f'/n{n}.receipt.json').stdout)
            save(fleet.root / f'n{n}.failure-receipt.json', receipt)
            fleet.download(gateway, remote, n, receipt)
            return False
        except Exception:
            save(fleet.root / 'bastion-retained-for-recovery.json', dict(at=utc(), reason='sole compact evidence copy not downloaded; all workers released', bastion=gateway))
            return True

    def run_campaign(self, args):
        root = Path(args.out).resolve()
        manifest = read(root / 'payload-manifest.json')
        assert sha(__file__) == manifest['driver_sha256']
        assert manifest['scenario'] == self.scenario, 'scenario differs from frozen manifest'
        assert all((sha(Path(__file__).parent / name) == want for (name, want) in manifest['dependencies_sha256'].items()))
        assert read(root / 'baseline-r1/audit.json')['valid'], 'preserve and verify first-run node results before launching'
        previous = int((root / 'controller.pid').read_text()) if (root / 'controller.pid').exists() else None
        assert previous is None or (args.action == 'resume' and (not process_alive(previous)))
        (root / 'controller.pid').write_text(str(os.getpid()))
        save(root / 'status.json', dict(state='preparing', pid=os.getpid(), updated_at=utc()))
        fleet = self.Fleet(root)
        gateway = None
        complete = False
        keep_bastion = False
        n = 0
        try:
            fleet.discover()
            gateway = self.acquire_bastion(fleet, args.action == 'resume')
            fleet.data['bastion'] = gateway
            fleet.persist()
            self.wait_bastion(fleet, gateway)
            save(root / 'bastion-preflight.json', json.loads(fleet.control(gateway, 'python3 -c ' + shlex.quote(PROBE)).stdout))
            remote = '/home/ubuntu/' + fleet.name
            fleet.control(gateway, 'mkdir -p ' + shlex.quote(remote + '/payload'))
            files = [root / 'protocol.tar.gz', root / 'payload-manifest.json', root / 'control-key', root / 'plan.json', Path(__file__)] + [Path(__file__).parent / name for name in manifest['dependencies_sha256']]
            for path in files:
                if path.name == 'plan.json':
                    public = dict(campaign=fleet.name)
                    save(root / 'remote-plan.json', public)
                    path = root / 'remote-plan.json'
                    fleet.ssh.put(gateway, path, remote + '/plan.json')
                else:
                    fleet.ssh.put(gateway, path, remote + '/' + path.name)
            fleet.control(gateway, 'chmod 600 ' + remote + '/control-key; tar -xzf ' + remote + '/protocol.tar.gz -C ' + remote + '/payload; chmod +x ' + remote + '/payload/bin/*')
            for n in SIZES:
                if (root / f'n{n}.local-audit.json').exists():
                    assert read(root / f'n{n}.local-audit.json')['valid']
                    continue
                save(root / 'status.json', dict(state='running', phase='provision', n=n, pid=os.getpid(), updated_at=utc()))
                fleet.grow(n)
                fleet.telemetry(f'n{n}-before')
                inventory = dict(campaign=fleet.name, n=n, regions=fleet.regions, candidates=fleet.refresh())
                path = root / f'inventory-n{n}.private.json'
                save(path, inventory)
                fleet.ssh.put(gateway, path, remote + '/inventory.json')
                save(root / 'status.json', dict(state='running', phase='bastion', n=n, pid=os.getpid(), updated_at=utc()))
                exit_code = fleet.remote_job(gateway, remote, n)
                assert exit_code == 0, 'size job failed; collect bounded diagnostics then release workers'
                self.collect_size(fleet, gateway, remote, n)
                emit('size-collected', n=n, bytes=read(root / f'n{n}.receipt.json')['bytes'], worker_release_before_download=True)
            complete = True
        except BaseException:
            save(root / 'failure.private.json', dict(at=utc(), traceback=traceback.format_exc()))
            if gateway:
                try:
                    code = 'from pathlib import Path; import json,subprocess,os,signal; r=Path(' + repr('/home/ubuntu/' + fleet.name) + "); p=r/'jobs'/" + repr(f'n{n}.pid') + "; pid=int(p.read_text()) if p.exists() else 0; cmd=Path('/proc')/str(pid)/'cmdline'; assert not cmd.exists() or str(r).encode() in cmd.read_bytes(); os.kill(pid,signal.SIGTERM) if pid and cmd.exists() else None; hosts=[h for f in (r/'results').glob('*/units.json') for h in json.loads(f.read_text())]; [(subprocess.run(['ssh','-i',str(r/'control-key'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','ubuntu@'+h['ip'],'sudo systemctl stop '+h['unit']],timeout=30)) for h in hosts]; print('stopped')"
                    fleet.control(gateway, 'python3 -c ' + shlex.quote(code), timeout=600, check=False)
                except Exception:
                    pass
                fleet.release_workers(n, gateway)
                keep_bastion = self.preserve_failure_bundle(fleet, gateway, remote, n)
            raise
        finally:
            if not keep_bastion:
                fleet.terminate()
            save(root / 'status.json', dict(state='complete' if complete else 'failed', phase='collected' if complete else 'preserved', pid=os.getpid(), updated_at=utc()))
        if complete:
            self.summarize(root)

    def summarize(self, root, pdf=False):
        plan = read(root / 'plan.json')
        baseline = read_csv(plan['baseline_summary_path'])
        rows = []
        keys = ('throughput_outputs_per_second', 'sent_kib_per_beacon_per_node', 'cpu_utilization_percent', 'cpu_ms_per_beacon', 'actual_cpu_cores', 'outputs_per_cpu_second_per_node')
        for old in baseline:
            assert old['warmup'] == '200' and old['intervals'] == '400'
            rows.append(dict(protocol=old['protocol'], n=int(old['n']), repetition=1, faults_injected=0, outputs=600, warmup=200, intervals=400, nodes=int(old['n']), **{k: float(old[k]) for k in keys}))
        node_rows = read_csv(plan['baseline_nodes_path'])
        for n in SIZES:
            audit = read(root / f'n{n}.local-audit.json')
            assert audit['valid']
            rows += audit['rows']
            node_rows += audit['node_rows']
        rows.sort(key=lambda r: (self.protocols.index(r['protocol']), r['n'], r['repetition']))
        assert len(rows) == 45 and len(node_rows) == 2880
        assert {(r['protocol'], r['n'], r['repetition']) for r in rows} == {(p, n, r) for p in self.protocols for n in SIZES for r in (1, 2, 3)}
        write_csv(root / 'results.csv', rows)
        write_csv(root / 'per-node.csv', node_rows)
        means = []
        for p in self.protocols:
            for n in SIZES:
                group = [r for r in rows if r['protocol'] == p and r['n'] == n]
                means.append(dict(protocol=p, n=n, repetitions=3, **{k: statistics.mean((r[k] for r in group)) for k in keys}))
        write_csv(root / 'mean.csv', means)
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        plt.rcParams.update({'pdf.fonttype': 42, 'svg.fonttype': 'none'})
        (fig, axes) = plt.subplots(1, 3, figsize=(17, 5.4))
        for (ax, (key, label)) in zip(axes, [(keys[0], 'Throughput (beacons/s)'), (keys[1], 'Application Tx (KiB/beacon/node)'), (keys[2], 'CPU utilization (% of 2-vCPU quota)')]):
            for (p, color, marker) in [('asyrand', '#347dc1', 'o'), ('grandline', '#2b9365', '^'), ('spurt', '#df8827', 's')]:
                ax.plot(SIZES, [r[key] for r in means if r['protocol'] == p], label={'asyrand': 'AsyRand', 'grandline': 'Grandline', 'spurt': 'SPURT'}[p], color=color, marker=marker, lw=2)
            ax.set(xticks=SIZES, xlabel='Committee size n', ylabel=label, ylim=(0, 105) if key == keys[2] else (0, None))
            ax.grid(axis='y', alpha=0.2)
        fig.legend(*axes[0].get_legend_handles_labels(), loc='upper center', ncol=3, frameon=False)
        fig.text(0.06, 0.025, 'Mean of 3 no-fault runs per point; each run: 600 outputs, first 200 warmup, completion 200-to-600 / 400.\nEach run uses means over all n honest nodes. Native AWS 2 vCPU / 4 GiB; application Tx excludes self-delivery and TLS/TCP.\nRun 1 is the previous independent campaign; runs 2 and 3 use fresh processes and per-run setup; no significance claim.', fontsize=8)
        fig.tight_layout(rect=(0, 0.21, 1, 0.91))
        for ext in ('png', 'svg') + (('pdf',) if pdf else ()):
            fig.savefig(root / f'combined.{ext}', dpi=300, bbox_inches='tight')
        plt.close(fig)
        save(root / 'analysis.json', dict(valid=True, cells=45, node_results=2880, mean_points=15, window='200-to-600/400', results_sha256=sha(root / 'results.csv'), per_node_sha256=sha(root / 'per-node.csv'), mean_sha256=sha(root / 'mean.csv'), faults_injected=0))


SCENARIOS = {'single': SingleCampaign, 'silent': SilentCampaign, 'repeat': RepeatCampaign}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'resume', 'remote', 'inspect',
                                          'bundle', 'analyze', 'compact-node', 'compact-baseline'))
    parser.add_argument('--scenario', choices=SCENARIOS, default='single')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--settings', type=Path, default=REPO / 'benchmark/settings.json')
    parser.add_argument('--campaign')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--nodes', type=int, default=0)
    parser.add_argument('--pdf', action='store_true')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--folder', type=Path)
    parser.add_argument('--protocol', choices=compact.PROTOCOLS)
    parser.add_argument('--repetition', type=int)
    parser.add_argument('--epochs', type=int, default=600)
    args = parser.parse_args(argv)
    if args.action == 'compact-node':
        if args.folder is None or args.protocol is None or args.nodes < 1 or args.repetition is None:
            parser.error('compact-node requires --folder, --protocol, --nodes and --repetition')
        result = compact.build_result(args.folder, args.protocol, args.nodes, args.repetition, args.epochs)
        (args.folder / 'node-result.json').write_text(json.dumps(result, separators=(',', ':')) + '\n')
        print(json.dumps(result, separators=(',', ':')))
        return
    if args.out is None:
        parser.error('--out is required for this action')
    root = args.out.resolve()
    if args.action == 'compact-baseline':
        if args.source is None:
            parser.error('compact-baseline requires --source')
        compact.compact_baseline(args.source, root)
        return
    driver = SCENARIOS[args.scenario]()
    if args.action == 'prepare':
        driver.prepare(args)
    elif args.action in ('run', 'resume'):
        driver.run_campaign(args)
    elif args.action == 'remote':
        if args.inventory is None:
            parser.error('remote requires --inventory')
        try:
            driver.remote_size(root, read(args.inventory))
        except BaseException:
            save(root / 'status.json', dict(state='failed', pid=os.getpid(), updated_at=utc(), traceback=traceback.format_exc()))
            raise
    elif args.action == 'bundle':
        if args.scenario == 'repeat':
            driver.bundle(root, args.nodes, failed=True)
        else:
            driver.bundle(root, args.nodes)
    elif args.action == 'analyze':
        if args.scenario == 'repeat':
            driver.summarize(root, args.pdf)
        else:
            driver.summarize(root)
    else:
        fleet = driver.Fleet(root)
        rows = fleet.refresh()
        remote = None
        gateway = fleet.data.get('bastion')
        if gateway and any(h['id'] == gateway['id'] and h['state'] == 'running' for h in rows):
            try:
                remote = read_remote(fleet.ssh, gateway, 'cat /home/ubuntu/' + fleet.name + '/status.json')
            except Exception as error:
                remote = dict(control_error=type(error).__name__)
        emit('inspection', local=read(root / 'status.json'), remote=remote, instances=len(rows),
             by_region={r: sum(h['region'] == r for h in rows) for r in fleet.regions})


if __name__ == '__main__':
    main()
