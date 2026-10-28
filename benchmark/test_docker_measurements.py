"""Offline measurement, evidence and AWS orchestration regressions."""
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from docker_bench import generation_metrics
import io
import os
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import aws_bench as driver
import aws_common as common
import bench_results as compact

result_io = compact
single = driver.SingleCampaign()
silent = driver.SilentCampaign()
repeat = driver.RepeatCampaign()
BENCH = Path(__file__).resolve().parent


class MeasurementBoundary(unittest.TestCase):
    def fixture(self, root, cores=1, start=100):
        (root / 'node0').mkdir()
        manifest = {'resources': {'cpu_cores_per_node': cores}, 'measurement': {
            'start_output_count': start, 'scope': f'output-{start}-to-output-600'}}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        base = datetime(2026, 10, 25, tzinfo=timezone.utc)
        events = [dict(outputs=c,time=(base+timedelta(seconds=c*.02)).isoformat(),
                       cpu_usage_usec=c*10000, traffic={'SentBytes':c*1024,'RecvBytes':c*2048},
                       memory_peak='1048576',memory_current='524288')
                  for c in (1,100,200,300,400,500,600)]
        (root/'node0/measurement.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))

    def test_last_500_uses_completion_100_not_101(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root)
            m=generation_metrics(root,1,600)['nodes'][0]
            self.assertEqual(m['intervals'],500)
            self.assertEqual(m['elapsed_s'],10)
            self.assertEqual(m['throughput_outputs_per_second'],50)
            self.assertEqual(m['sent_kib_per_beacon_per_node'],1)
            self.assertEqual(m['cpu_ms_per_beacon'],10)
            self.assertEqual(m['cpu_utilization_percent'],50)

    def test_two_cpu_percent_is_quota_normalized(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root,cores=2)
            self.assertEqual(generation_metrics(root,1,600)['nodes'][0]['cpu_utilization_percent'],25)

    def test_missing_boundary_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.fixture(root,start=101)
            with self.assertRaisesRegex(ValueError,'missing start checkpoint'):
                generation_metrics(root,1,600)


class AwsRefactorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (BENCH / 'local').mkdir(exist_ok=True)

    def test_committee_threshold_and_per_run_setup(self):
        for protocol in result_io.PROTOCOLS:
            for n in (16, 31, 121):
                hosts = [dict(ip=f'192.0.2.{i + 1}') for i in range(n)]
                first = single.native_config(protocol, n, 600, hosts, 'campaign')
                second = repeat.native_config(protocol, n, 600, hosts, 'campaign', 2)
                self.assertEqual(len(first['cluster_index']), n)
                self.assertEqual(first['f'], (n - 1) // 3)
                self.assertEqual(first['round'], 600)
                self.assertNotEqual(first['session_id'], second['session_id'])
                self.assertEqual(first['peers_p2p_port'], second['peers_p2p_port'])
                self.assertEqual(first['adaptive_production_window'], protocol == 'asyrand')
                self.assertEqual(first['production_window_min'], 2)
                self.assertEqual(first['production_window_max'], 8)

    def test_silent_keeps_full_committee(self):
        hosts = [dict(ip=f'192.0.2.{i + 1}') for i in range(16)]
        config = silent.native_config('asyrand', 16, 600, hosts, 'silent')
        self.assertEqual(len(config['cluster_index']), 16)
        self.assertEqual(config['f'], 5)
        with patch.object(driver.measured, 'validate', return_value=dict(run_valid=True)) as validate:
            result = silent.validate_honest(['log'] * 15, 16, 600)
        validate.assert_called_once_with(['log'] * 15, 15, 600, 'asyrand')
        self.assertEqual(result['silent_node'], 'node15')
        self.assertEqual(result['honest_nodes'], 15)

    def test_window_metrics_use_common_400_boundaries(self):
        start = dict(outputs=200, time='2026-10-28T00:00:00Z', cpu_usage_usec=2_000_000,
                     traffic=dict(SentBytes=2000, RecvBytes=3000))
        end = dict(outputs=600, time='2026-10-28T00:00:02Z', cpu_usage_usec=5_000_000,
                   traffic=dict(SentBytes=411600, RecvBytes=822200),
                   memory_peak=2**20, memory_current=2**19)
        metrics = compact.metrics(start, end)
        self.assertEqual(metrics['intervals'], 400)
        self.assertEqual(metrics['throughput_outputs_per_second'], 200)
        self.assertEqual(metrics['sent_kib_per_beacon_per_node'], 1)
        self.assertEqual(metrics['cpu_utilization_percent'], 75)
        self.assertEqual(metrics['actual_cpu_cores'], 1.5)
        self.assertEqual(metrics['cpu_ms_per_beacon'], 7.5)
        with self.assertRaises(AssertionError):
            compact.metrics(dict(start, outputs=201), end)

    def stage(self, folder, driver, protocols, compact_mode, scenario='single'):
        repo = folder / 'repo'
        source = repo / 'source.go'
        source.parent.mkdir()
        source.write_text('verified protocol source')
        frozen = repo / 'benchmark/runs/frozen-final-20261026/runtime'
        (frozen / 'bin').mkdir(parents=True)
        for name in result_io.PROTOCOLS:
            (frozen / 'bin' / name).write_text('verified-' + name)
        result_io.save(frozen / 'source-manifest.json', dict(
            files_sha256={'source.go': result_io.sha(source)},
            binaries_sha256={p.name: result_io.sha(p) for p in (frozen / 'bin').iterdir()}))
        out = folder / 'campaign'
        out.mkdir()
        with patch.object(common, 'REPO', repo):
            manifest = common.stage_payload(out, BENCH / driver, protocols, compact_mode, scenario=scenario)
        result_io.save(out / 'payload-manifest.json', manifest)
        return out, manifest

    def test_standalone_controller_and_worker_dependencies_are_packaged(self):
        for scenario, protocols, compact_mode in (
            ('single', result_io.PROTOCOLS, False),
            ('silent', ('asyrand',), False),
            ('repeat', result_io.PROTOCOLS, True),
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
                folder = Path(tmp)
                driver = 'aws_bench.py'
                out, manifest = self.stage(folder, driver, protocols, compact_mode, scenario)
                self.assertEqual(set(manifest['deployed_binaries_sha256']), set(protocols))
                copied = folder / 'standalone'
                common.safe_extract(out / 'source.tar.gz', copied)
                driver_path = copied / 'benchmark' / driver
                common.verify_controller(driver_path, out, scenario)
                env = dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1')
                command = subprocess.run([sys.executable, '-B', str(driver_path), '--scenario', scenario, '--help'],
                                         cwd=folder, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(command.returncode, 0, command.stderr)
                with tarfile.open(out / 'protocol.tar.gz') as archive:
                    names = set(archive.getnames())
                self.assertEqual({n.split('/')[-1] for n in names if n.startswith('bin/')}, set(protocols))
                if compact_mode:
                    self.assertIn('bench_results.py', names)
                    self.assertNotIn('aws_silent_bench.py', manifest['dependencies_sha256'])
                    worker = subprocess.run([sys.executable, '-B', str(out / 'payload/bench_results.py'), '--help'],
                                            cwd=folder, env=env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(worker.returncode, 0, worker.stderr)

    def test_changed_dependency_is_rejected_before_cloud_initialization(self):
        with tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
            root = Path(tmp)
            for path in common.controller_files(single.__file__):
                shutil.copy2(path, root / path.name)
            driver = root / 'aws_bench.py'
            result_io.save(root / 'payload-manifest.json', dict(
                driver_sha256=result_io.sha(driver), dependencies_sha256=common.dependency_hashes(driver)))
            common.verify_controller(driver, root)
            (root / 'bench_results.py').write_text('modified dependency')
            scenario = SimpleNamespace(__file__=str(driver), scenario='single', Fleet=Mock())
            with self.assertRaisesRegex(AssertionError, 'dependency differs'):
                common.run_campaign(SimpleNamespace(out=root), scenario)
            scenario.Fleet.assert_not_called()

    def test_wrong_scenario_is_rejected_before_cloud_initialization(self):
        with tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
            out, manifest = self.stage(Path(tmp), 'aws_bench.py', ('asyrand',), False, 'silent')
            scenario = SimpleNamespace(__file__=str(BENCH / 'aws_bench.py'), scenario='single', Fleet=Mock())
            with self.assertRaisesRegex(AssertionError, 'scenario differs'):
                common.run_campaign(SimpleNamespace(out=out), scenario)
            scenario.Fleet.assert_not_called()

    def test_silent_probe_keeps_the_remote_campaign_path(self):
        ssh = Mock()
        ssh.call.return_value.stdout = json.dumps(dict(valid=True, protocol_pids=[], listening_9000=False))
        host = dict(id='silent-host', node=15)
        result = silent.silence_probe(ssh, host, '/home/ubuntu/campaign')
        self.assertTrue(result['valid'])
        self.assertIn('/home/ubuntu/campaign', ssh.call.call_args.args[1])
        self.assertNotIn('<module', ssh.call.call_args.args[1])

    def test_bastion_is_excluded_from_region_balanced_committee(self):
        hosts = [dict(id=f'{r}{i}', region=r, role='candidate') for r in ('a', 'b') for i in range(3)]
        hosts.append(dict(id='gateway', region='a', role='bastion'))
        chosen = common.placement(hosts, 4, ('a', 'b'))
        self.assertEqual([h['region'] for h in chosen], ['a', 'b', 'a', 'b'])
        self.assertNotIn('gateway', [h['id'] for h in chosen])

    def test_archive_traversal_and_symlinks_are_rejected(self):
        for name, link in (('../escape', False), ('C:/escape', False), ('safe/link', True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
                root = Path(tmp)
                archive_path = root / 'bad.tar'
                with tarfile.open(archive_path, 'w') as archive:
                    item = tarfile.TarInfo(name)
                    if link:
                        item.type = tarfile.SYMTYPE
                        item.linkname = '/outside'
                        archive.addfile(item)
                    else:
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b'x'))
                with self.assertRaises(AssertionError):
                    common.safe_extract(archive_path, root / 'extracted')

    def test_compact_transfer_occurs_only_after_worker_release(self):
        with tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
            receipt = dict(valid=True)
            events = []
            fleet = SimpleNamespace(root=Path(tmp), control=Mock(return_value=SimpleNamespace(stdout=json.dumps(receipt))),
                release_workers=lambda *args: events.append('release'),
                download=lambda *args: events.append('download'))
            with patch.object(repeat, 'verify_ready'), patch.object(repeat, 'audit_stage', side_effect=lambda *args: events.append('audit')):
                repeat.collect_size(fleet, {'id': 'gateway'}, '/campaign', 16)
            self.assertEqual(events, ['release', 'download', 'audit'])

    def test_node_collection_preserves_each_result_and_checks_agreement(self):
        with tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
            root = Path(tmp)
            out = root / 'cell'
            out.mkdir()
            result_io.save(root / 'plan.json', dict(campaign='tyche-aws-test'))
            ssh = Mock()
            ssh.call.return_value.stdout = json.dumps(dict(beacons_sha256='matching-output'))
            hosts = [dict(node=i, folder=f'/campaign/node{i}') for i in range(2)]
            with patch.object(driver.compact, 'verify_result') as verify:
                rows = repeat.collect_nodes(root, out, hosts, ssh, 'asyrand', 2, 600)
            self.assertEqual(len(rows), 2)
            self.assertEqual(verify.call_count, 4)
            for i in range(2):
                self.assertEqual(result_io.read(out / f'node{i}.json')['beacons_sha256'], 'matching-output')
            self.assertTrue(all('payload/bench_results.py' in c.args[1] for c in ssh.call.call_args_list))

    def test_foreign_volume_prevents_termination(self):
        with tempfile.TemporaryDirectory(dir=BENCH / 'local') as tmp:
            fleet = repeat.Fleet.__new__(repeat.Fleet)
            fleet.root = Path(tmp)
            fleet.name = 'tyche-aws-test'
            fleet.regions = ['region']
            gateway = dict(id='gateway', role='bastion', region='region')
            worker = dict(id='worker', role='candidate', region='region')
            fleet.refresh = Mock(return_value=[gateway, worker])
            client = Mock()
            client.describe_instances.return_value = dict(Reservations=[dict(Instances=[dict(
                Tags=[dict(Key='TycheCampaign', Value=fleet.name)])])])
            client.describe_volumes.return_value = dict(Volumes=[dict(VolumeId='foreign',
                Tags=[dict(Key='TycheCampaign', Value='another-campaign')])])
            fleet.clients = {'region': client}
            with self.assertRaises(AssertionError):
                fleet.release_workers(16, gateway)
            client.terminate_instances.assert_not_called()

    def test_offline_baseline_does_not_import_aws_workflows(self):
        code = "import bench_results,sys; assert not any(n in sys.modules for n in ('aws_bench','aws_common','boto3')); print('offline')"
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=BENCH,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__=='__main__':unittest.main()
