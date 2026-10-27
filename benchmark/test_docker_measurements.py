"""Check the output-count boundary and CPU quota normalization, without Docker."""
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from docker_bench import generation_metrics


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


if __name__=='__main__':unittest.main()
