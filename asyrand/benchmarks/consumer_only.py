#!/usr/bin/env python3
"""Measure the current Consumer implementation without rerunning baseline protocols."""
import argparse,csv,json,os,re,subprocess,time,statistics,hashlib
from pathlib import Path
from datetime import datetime,timezone
root=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--out',type=Path);parser.add_argument('--parallel',action=argparse.BooleanOptionalAction,default=True);args=parser.parse_args()
out=(args.out or root/'asyrand/benchmarks'/('consumer_v2_'+datetime.now().strftime('%Y%m%d_%H%M%S'))).resolve();out.mkdir(parents=True,exist_ok=False)
binary=args.binary.resolve()
env=dict(os.environ,GOMAXPROCS='8');rows=[]
def stamp(s):
 m=re.fullmatch(r'(.+?)(?:\.(\d+))?Z',s);return int(datetime.strptime(m[1],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp())*10**9+int((m[2] or '').ljust(9,'0'))
for n in [4,8]:
 for repeat in range(1,4):
  c=json.loads((root/f'asyrand/configs/local_{n}.json').read_text());c.update(round=257,warmup_outputs=0,epoch_timeout_ms=30000,prefill_ms=3000,report_interval_ms=60000,production_window=8,max_pool=4,parallel_consumption=args.parallel,session_id=f'{out.name}-{n}-{repeat}')
  tag=f'asyrand_v2_n{n}_r{repeat}';cfg=out/(tag+'.json');cfg.write_text(json.dumps(c,indent=2)+'\n');log=out/(tag+'.log');start=time.monotonic()
  with log.open('w') as lf:r=subprocess.run([str(binary),'-config',str(cfg)],cwd=root/'asyrand',env=env,stdout=lf,stderr=subprocess.STDOUT,timeout=600)
  data=log.read_text();packets=re.findall(r'^ts=(\S+) epoch=(\d+) .*random=',data,re.M);assert r.returncode==0 and len(packets)==257 and 'verification valid_epochs=257' in data and ' skipped ' not in data,log
  ts=[stamp(t) for t,e in packets][128:];elapsed=(ts[-1]-ts[0])/1e9;rps=128/elapsed;row=dict(protocol='asyrand-v2',nodes=n,repeat=repeat,warmup=128,intervals=128,elapsed_s=elapsed,beacon_s=rps,wall_s=time.monotonic()-start,log=log.name);rows.append(row)
  with (out/'results.csv').open('w',newline='') as fp:w=csv.DictWriter(fp,fieldnames=list(row));w.writeheader();w.writerows(rows)
  print(f'{tag}: {rps:.3f} beacon/s, public history valid',flush=True)
summary=[]
for n in [4,8]:
 v=[r['beacon_s'] for r in rows if r['nodes']==n];summary.append(dict(protocol='asyrand-v2',nodes=n,repeats=3,mean_beacon_s=statistics.mean(v),stdev_beacon_s=statistics.stdev(v)))
with (out/'summary.csv').open('w',newline='') as fp:w=csv.DictWriter(fp,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
h=hashlib.sha256()
for p in sorted((root/'asyrand').rglob('*.go')):h.update(str(p.relative_to(root/'asyrand')).encode());h.update(p.read_bytes())
(out/'environment.json').write_text(json.dumps(dict(protocol='asyrand-v2',gomaxprocs=8,workers_per_node=4,transport='memory',production_window=8,parallel_consumption=args.parallel,warmup=128,intervals=128,repeats=3,go=subprocess.check_output(['go','version'],text=True).strip(),source_sha256=h.hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),paper_sha256=hashlib.sha256((root/'paper/Asyrand.tex').read_bytes()).hexdigest(),note='The original v1 baseline comparison is historical; this run measures only the updated AsyRand v2 implementation.'),indent=2)+'\n')
print('Saved '+str(out),flush=True)
