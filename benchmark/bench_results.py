"""Node evidence, offline baseline conversion and shared result I/O."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import csv
import math
import re
import statistics
import tarfile
import hashlib
import json
import threading
import time

REPO = Path(__file__).resolve().parents[1]
SIZES = (16, 31, 61, 91, 121)
PROTOCOLS = ('spurt', 'grandline', 'asyrand')
LOCK = threading.RLock()

def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path = Path(path)
    with LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + '.partial')
        tmp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
        for attempt in range(8):
            try:
                tmp.replace(path)
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(.1)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(2**20), b''):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path,rows):
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with Path(path).open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)


def read_csv(path):
    with Path(path).open(encoding='utf-8',newline='') as stream:return list(csv.DictReader(stream))


sha_file = sha

def timestamp(value):
    value = re.sub(r'\.(\d+)', lambda m: '.' + m[1][:6].ljust(6, '0'), value.replace('Z', '+00:00'))
    return datetime.fromisoformat(value)


def beacon_hash(outputs):
    return hashlib.sha256(json.dumps(outputs, separators=(',', ':')).encode()).hexdigest()


def metrics(start, end, epochs=600, start_count=200, cores=2):
    assert start['outputs'] == start_count and end['outputs'] == epochs
    elapsed = (timestamp(end['time']) - timestamp(start['time'])).total_seconds()
    cpu = (end['cpu_usage_usec'] - start['cpu_usage_usec']) / 1e6
    sent = end['traffic']['SentBytes'] - start['traffic']['SentBytes']
    received = end['traffic']['RecvBytes'] - start['traffic']['RecvBytes']
    assert min(elapsed, cpu, sent, received) > 0
    intervals = epochs - start_count
    return dict(outputs=epochs, intervals=intervals, elapsed_s=elapsed, cpu_seconds=cpu,
                sent_bytes=sent, received_bytes=received,
                throughput_outputs_per_second=intervals / elapsed,
                sent_kib_per_beacon_per_node=sent / intervals / 1024,
                received_kib_per_beacon_per_node=received / intervals / 1024,
                cpu_utilization_percent=cpu / elapsed * 100 / cores,
                cpu_ms_per_beacon=cpu / intervals * 1000,
                actual_cpu_cores=cpu / elapsed,
                outputs_per_cpu_second_per_node=intervals / cpu,
                memory_peak_mib=int(end['memory_peak']) / 2**20,
                memory_end_mib=int(end['memory_current']) / 2**20)


def verify_result(result, reference_hash=None):
    assert result['valid'] and result['faults_injected'] == 0
    n, node, epochs = result['n'], result['node'], result['outputs']
    assert 0 <= node < n and result['fault_budget'] == (n - 1) // 3
    assert result['warmup'] == 200 and result['intervals'] == epochs - 200
    assert result['exit_code'] == 0 and result['oom_kill'] == 0 and result['cpu_cores'] == 2
    assert result['output_count'] == epochs and result['contiguous_outputs'] and result['benchmark_complete']
    assert result['generation_complete'] and result['verify_barrier_released']
    assert result['final_metrics']['beacons'] == str(epochs - 1)
    start, end = result['boundary_start'], result['boundary_end']
    assert timestamp(result['output_times']['200']) <= timestamp(start['time']) <= timestamp(result['output_times']['201'])
    assert timestamp(result['output_times'][str(epochs)]) <= timestamp(end['time'])
    recomputed = metrics(start, end, epochs)
    assert set(recomputed) == set(result['metrics'])
    assert all(math.isclose(v, result['metrics'][k], rel_tol=1e-12, abs_tol=1e-12) for k, v in recomputed.items())
    assert result['checkpoints'] == [1] + list(range(100, epochs, 100)) + [epochs]
    if result['protocol'] == 'asyrand':
        assert result['public_history_verified'] and result['history']['sha256']
        assert result['consumer_priority_enabled'] and result['consumption_prefetch_enabled']
    if 'beacons' in result:
        first = 1 if result['protocol'] == 'asyrand' else 0
        assert [v[0] for v in result['beacons']] == list(range(first, first + epochs))
        assert beacon_hash(result['beacons']) == result['beacons_sha256']
    if reference_hash is not None:
        assert result['beacons_sha256'] == reference_hash, 'cross-node output mismatch'
    return recomputed


def build_result(folder, protocol, n, repetition, epochs=600, history_receipt=None):
    folder = Path(folder)
    node = int(folder.name.removeprefix('node'))
    text = (folder / 'stdout.log').read_text(encoding='utf-8')
    found = re.findall(r'ts=(\S+)[^\n]*?epoch=(\d+)[^\n]*? random=([0-9a-f]+)', text)
    outputs = [[int(epoch), random] for _, epoch, random in found]
    first = 1 if protocol == 'asyrand' else 0
    assert [v[0] for v in outputs] == list(range(first, first + epochs))
    config = json.loads((folder / 'config.json').read_text())
    assert len(config['cluster_index']) == n and config['f'] == (n - 1) // 3 and config['round'] == epochs
    events = [json.loads(v) for v in (folder / 'measurement.jsonl').read_text().splitlines()]
    start = next(e for e in events if e['outputs'] == 200)
    end = events[-1]
    quota, period = map(int, (folder / 'cpu.max').read_text().split())
    assert quota == 2 * period
    memory = (folder / 'memory.events').read_text()
    oom = int(re.search(r'(?m)^oom_kill (\d+)$', memory)[1])
    exit_code = int((folder / 'node.exit').read_text().strip())
    final_lines = re.findall(r'^final metrics (.+)$', text, re.M)
    final = dict(re.findall(r'(\w+)=([^\s]+)', final_lines[-1])) if final_lines else {}
    history = None
    if protocol == 'asyrand':
        p = folder / 'history.json'
        if p.is_file():
            history = dict(sha256=sha_file(p), bytes=p.stat().st_size, retained=False,
                           origin='local file after fresh complete public-history verification')
        else:
            assert history_receipt is not None
            history = dict(sha256=history_receipt['files_sha256']['history.json'], retained=False,
                           origin='previously audited complete node archive receipt')
    hashes = {name: sha_file(folder / name) for name in
              ('stdout.log', 'measurement.jsonl', 'config.json', 'cpu.max', 'memory.events', 'node.exit')}
    result = dict(schema='tyche-node-result-v1', valid=True, protocol=protocol, n=n, node=node,
                  repetition=repetition, faults_injected=0, fault_budget=(n-1)//3, outputs=epochs,
                  warmup=200, intervals=epochs-200, output_count=len(outputs), contiguous_outputs=True,
                  beacons_sha256=beacon_hash(outputs),
                  output_times={'200': found[199][0], '201': found[200][0], str(epochs): found[epochs-1][0]},
                  benchmark_complete=f'benchmark_complete outputs={epochs}' in text,
                  generation_complete=(folder / 'generation-complete').is_file(),
                  verify_barrier_released=(folder / 'verify-start').is_file(),
                  public_history_verified=protocol != 'asyrand' or f'verification valid_epochs={epochs} ' in text,
                  history=history, exit_code=exit_code, oom_kill=oom, cpu_cores=quota/period,
                  cpu_max=[quota, period], checkpoints=[e['outputs'] for e in events],
                  boundary_start=start, boundary_end=end, metrics=metrics(start,end,epochs),
                  final_metrics=final, source_files_sha256=hashes,
                  consumer_priority_enabled=all(e.get('extra',{}).get('consumer_priority_enabled',False) for e in events),
                  consumption_prefetch_enabled=all(e.get('extra',{}).get('consumption_prefetch_enabled',False) for e in events))
    if node == 0:
        result['beacons'] = outputs
    verify_result(result)
    return result


def compact_baseline(source_root, out_root):
    old = Path(source_root).resolve()
    new = Path(out_root).resolve()
    destination=new/'baseline-r1';destination.mkdir(parents=True,exist_ok=True)
    summary=read_csv(old/'last400/summary.csv')
    original_nodes=read_csv(old/'last400/per-node.csv')
    original_analysis=read(old/'last400/analysis.json')
    nodes=[];cells=[];files={}
    for n in SIZES:
        for protocol in PROTOCOLS:
            cell=old/f'evidence/n{n}/results/{protocol}-n{n}-r1'
            target=destination/f'{protocol}-n{n}-r1';target.mkdir(exist_ok=True)
            results=[]
            for i in range(n):
                receipt=read(cell/f'node{i}.receipt.json')
                result=build_result(cell/f'node{i}',protocol,n,1,history_receipt=receipt)
                for name,digest in result['source_files_sha256'].items():
                    assert digest==receipt['files_sha256'][name],(cell,i,name)
                for name in ('stdout.log','measurement.jsonl'):
                    key=(cell/f'node{i}'/name).relative_to(old).as_posix()
                    assert result['source_files_sha256'][name]==original_analysis['input_files_sha256'][key]
                expected=next(row for row in original_nodes if row['protocol']==protocol and int(row['n'])==n and int(row['node'])==i)
                for key in ('elapsed_s','cpu_seconds','sent_bytes','received_bytes','throughput_outputs_per_second','sent_kib_per_beacon_per_node','cpu_utilization_percent','cpu_ms_per_beacon'):
                    assert math.isclose(result['metrics'][key],float(expected[key]),rel_tol=1e-12,abs_tol=1e-12),(protocol,n,i,key)
                path=target/f'node{i}.json';save(path,result);files[path.relative_to(destination).as_posix()]=sha(path)
                results.append(result)
                nodes.append(dict(protocol=protocol,n=n,repetition=1,node=i,start_output_count=200,end_output_count=600,
                    start_time=result['boundary_start']['time'],end_time=result['boundary_end']['time'],
                    **result['metrics'],result_path=path.relative_to(new).as_posix()))
            for result in results:verify_result(result,results[0]['beacons_sha256'])
            expected=next(row for row in summary if row['protocol']==protocol and int(row['n'])==n)
            for key in ('throughput_outputs_per_second','sent_kib_per_beacon_per_node','cpu_utilization_percent','cpu_ms_per_beacon'):
                assert math.isclose(statistics.mean(r['metrics'][key] for r in results),float(expected[key]),rel_tol=1e-12)
            for name in ('config.json','manifest.json','validation.json','generation-barrier.json'):
                save(target/name,read(cell/name));files[f'{target.name}/{name}']=sha(target/name)
            cells.append(dict(protocol=protocol,n=n,nodes=n,valid=True))
    assert len(nodes)==960 and len(cells)==15
    write_csv(destination/'per-node.csv',nodes)
    write_csv(destination/'summary.csv',summary)
    save(destination/'audit.json',dict(valid=True,cells=15,node_results=960,all_original_400_metrics_reproduced=True,
        original_summary_sha256=sha(old/'last400/summary.csv'),original_per_node_sha256=sha(old/'last400/per-node.csv'),
        original_960_boundary_and_log_sha_verified=True,checked_at=utc(),files_sha256=files))
    package=new/'baseline-r1.tar.gz'
    with tarfile.open(package,'w:gz',compresslevel=6) as archive:
        for path in sorted(destination.rglob('*')):
            if path.is_file():archive.add(path,arcname=path.relative_to(destination).as_posix(),recursive=False)
    with tarfile.open(package) as archive:
        for member in archive:
            assert member.isfile() and member.name not in ('control-key','known_hosts')
            if member.name in files:
                import hashlib
                assert hashlib.sha256(archive.extractfile(member).read()).hexdigest()==files[member.name]
    save(new/'baseline-compaction.json',dict(valid=True,node_results=960,cells=15,package=package.name,bytes=package.stat().st_size,
        sha256=sha(package),original_logs_pruning_authorized=True,original_raw_files_not_deleted_yet=True,created_at=utc()))
    print(json.dumps(dict(valid=True,node_results=960,compact_archive_bytes=package.stat().st_size)))


def collect_node(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--protocol', choices=('asyrand', 'grandline', 'spurt'), required=True)
    parser.add_argument('--nodes', type=int, required=True)
    parser.add_argument('--repetition', type=int, required=True)
    parser.add_argument('--epochs', type=int, default=600)
    args = parser.parse_args(argv)
    result = build_result(args.folder, args.protocol, args.nodes, args.repetition, args.epochs)
    output = args.folder / 'node-result.json'
    output.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    collect_node()
