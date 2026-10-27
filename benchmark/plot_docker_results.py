"""Render verified Docker measurements in Silk's academic figure style.

Mean mode follows Silk's current figure convention: equal-weight arithmetic
means across replicas within each run, then across three runs. Median mode
preserves the aggregation used in this campaign's initial result summary.
"""
import argparse
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys

from docker_bench import validate, generation_metrics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


NODES = (7, 16, 31, 61)
PROTOCOLS = ("spurt", "grandline", "asyrand")
DISPLAY = {"spurt": "SPURT", "grandline": "Grandline", "asyrand": "AsyRand", "asyrand-w2": "AsyRand W=2", "asyrand-w8":"AsyRand W=8"}
# Palette, typography, white marker edges and line weights from Silk's
# code/experiments/plots/fig3.py and bandwidth.py. Keep SPURT's green triangle.
COLORS = {"spurt": "#35A88A", "grandline": "#F0A44B", "asyrand": "#56B4E9", "asyrand-w2": "#8B6BB1"}
COLORS['asyrand-w8']=COLORS['asyrand']
MARKERS = {"spurt": "^", "grandline": "s", "asyrand": "o", "asyrand-w2": "D"}
MARKERS['asyrand-w8']=MARKERS['asyrand']
LINES = {"spurt": "-.", "grandline": "--", "asyrand": "-", "asyrand-w2": ":"}
LINES['asyrand-w8']=LINES['asyrand']
DISPLAY['asyrand-adaptive-w8']='AsyRand adaptive W'
COLORS['asyrand-adaptive-w8']='#8B6BB1'
MARKERS['asyrand-adaptive-w8']='D'
LINES['asyrand-adaptive-w8']=':'
STYLE = {
    "font.family": ["Arial", "DejaVu Sans"], "font.size": 7.5,
    "axes.titlesize": 8.2, "axes.titleweight": "normal",
    "axes.titlelocation": "center", "axes.titlepad": 10,
    "axes.labelsize": 7.5, "axes.labelpad": 4,
    "axes.edgecolor": "#707070", "axes.linewidth": 0.55,
    "axes.spines.top": False, "axes.spines.right": False,
    "text.color": "#222222", "axes.labelcolor": "#222222",
    "xtick.color": "#333333", "ytick.color": "#333333",
    "xtick.major.width": 0.5, "ytick.major.width": 0.5,
    "xtick.major.size": 2.5, "ytick.major.size": 2.5,
    "legend.fontsize": 7, "legend.frameon": False,
    "pdf.fonttype": 42, "ps.fonttype": 42,
    "svg.fonttype": "none", "savefig.facecolor": "white",
}
METRICS = (
    ("throughput_outputs_per_second", "Beacon throughput", "Throughput (outputs/s)"),
    ("sent_kib_per_beacon_per_node", "Sent data per beacon", "Sent data (KiB/beacon/node)"),
    ("cpu_utilization_percent_approx", "Whole-container CPU (approx.)", "CPU (% of 1 vCPU)"),
)
# Retain earlier Tx+Rx metrics in the CSV for campaign comparisons. The main
# communication panel uses the recorded sending side, as in Silk's paper.
SUMMARY_METRICS = tuple(metric for metric, _, _ in METRICS) + (
    "communication_kib_per_beacon_per_node", "bandwidth_mib_per_second",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def timestamp(value):
    # Docker timestamps can contain nanoseconds; Python 3.10 accepts microseconds.
    value = re.sub(r"\.(\d+)",lambda m:"."+m[1][:6].ljust(6,"0"),value.replace("Z","+00:00"))
    return datetime.fromisoformat(value)


def measurements(campaign, aggregation, protocols=PROTOCOLS):
    audit_path = campaign/"audit.json"
    inventory_path = campaign/"artifacts-sha256.json"
    audit = load(audit_path) if audit_path.exists() else None
    inventory = load(inventory_path)["files_sha256"] if inventory_path.exists() else None
    if audit is not None and not audit.get("complete"):
        raise ValueError("Expected an independently verified complete campaign")
    audited = {c["cell"]:c for c in audit["cells"] if c["valid"]} if audit else None
    inputs = {str(p.resolve()):sha(p) for p in (audit_path,inventory_path) if p.exists()}
    reduce = statistics.fmean if aggregation == "mean" else statistics.median
    rows = []
    for n in NODES:
        for protocol in protocols:
            for rep in range(1,4):
                name = f"{protocol}-n{n}-r{rep}"
                if audited is not None and name not in audited:
                    raise ValueError(f"Unverified cell {name}")
                for filename in ("validation.json", "config.json", "manifest.json", "containers-final.json"):
                    p = campaign/name/filename
                    digest = sha(p)
                    if inventory is not None and inventory.get(f"{name}/{filename}") != digest:
                        raise ValueError(f"Changed source artifact: {p}")
                    inputs[str(p.resolve())] = digest
                report = load(campaign/name/"validation.json")
                cfg = load(campaign/name/"config.json")
                manifest = load(campaign/name/"manifest.json")
                inspections = load(campaign/name/"containers-final.json")
                logs = []
                for i in range(n):
                    path = campaign/name/f"node{i}/stdout.log"
                    digest = sha(path)
                    if inventory is not None and inventory.get(f"{name}/node{i}/stdout.log") != digest:
                        raise ValueError(f"Changed node log: {path}")
                    inputs[str(path.resolve())] = digest
                    logs.append(path.read_text(encoding="utf-8"))
                checked = validate(logs,n,200,protocol)
                if not checked["run_valid"] or checked["nodes"] != report["nodes"]:
                    raise ValueError(f"Saved measurements disagree with node logs: {name}")
                starts={c["Config"]["Cmd"][c["Config"]["Cmd"].index("-node")+1]:timestamp(c["State"]["StartedAt"]) for c in inspections}
                finished=timestamp(manifest["finished_at"])
                if not report["run_valid"] or len(report["nodes"]) != n or cfg["round"] != 200:
                    raise ValueError(f"Incomplete workload in {name}")
                if {int(node["node"]) for node in report["nodes"]} != set(range(n)):
                    raise ValueError(f"Wrong replica set in {name}")
                rates, sent, communication, bandwidth, cpu = [], [], [], [], []
                for node in report["nodes"]:
                    metrics = node["metrics"]
                    count, elapsed = int(metrics["beacons"]), float(metrics["elapsed_s"])
                    sent_bytes = int(metrics["sent_bytes"])
                    recv_bytes = int(metrics["recv_bytes"])
                    if node["errors"] or node["outputs"] != 200 or count != 199 or elapsed <= 0 or min(sent_bytes,recv_bytes) < 0:
                        raise ValueError(f"Invalid measurement window in {name}")
                    rate = count/elapsed
                    if not math.isclose(rate,node["throughput_outputs_per_second"],rel_tol=1e-12):
                        raise ValueError(f"Throughput mismatch in {name}")
                    rates.append(rate)
                    # Normalize each node's aligned measurement window before
                    # averaging. Dividing mean bandwidth by mean throughput
                    # would give a different, throughput-weighted quantity.
                    # These historical counters include local self-delivery;
                    # the logs cannot separate it from inter-node sends.
                    sent.append(sent_bytes/count/2**10)
                    communication.append((sent_bytes+recv_bytes)/count/2**10)
                    bandwidth.append((sent_bytes+recv_bytes)/elapsed/2**20)
                    relative=f"{name}/node{node['node']}/resource-network.txt"
                    counter_path=campaign/relative
                    digest=sha(counter_path)
                    if inventory is not None and inventory.get(relative) != digest:
                        raise ValueError(f"Changed cgroup evidence: {counter_path}")
                    inputs[str(counter_path.resolve())]=digest
                    usage=re.search(r"(?m)^usage_usec (\d+)$",counter_path.read_text(encoding="utf-8"))
                    if usage is None:
                        raise ValueError(f"Missing measured CPU counter: {counter_path}")
                    wall=(finished-starts[f"node{node['node']}"]).total_seconds()
                    if wall<=0:
                        raise ValueError(f"Invalid container lifetime in {name}")
                    cpu_percent=int(usage.group(1))/1e6/wall*100
                    if not 0<=cpu_percent<=100.5:
                        raise ValueError(f"CPU utilization inconsistent with the 1 vCPU quota: {name}")
                    cpu.append(cpu_percent)
                rows.append(dict(protocol=protocol, n=n, repetition=rep,
                    emitted_outputs=200, measured_intervals=199,
                    throughput_outputs_per_second=reduce(rates),
                    sent_kib_per_beacon_per_node=reduce(sent),
                    communication_kib_per_beacon_per_node=reduce(communication),
                    bandwidth_mib_per_second=reduce(bandwidth),
                    cpu_utilization_percent_approx=reduce(cpu),
                    production_window=cfg.get("production_window",8) if protocol == "asyrand" else "",
                    go_memory_limit=manifest.get("runtime_policy",{}).get("go_memory_limit","default"),
                    recovery_interval_ms=cfg.get("recovery_interval_ms",1000)))
    summary = []
    for n in NODES:
        for protocol in protocols:
            selected = [r for r in rows if r["n"] == n and r["protocol"] == protocol]
            row = dict(protocol=protocol,n=n,runs=3,aggregation=aggregation)
            for metric in SUMMARY_METRICS:
                values = [r[metric] for r in selected]
                if not all(math.isfinite(v) and v>0 for v in values):
                    raise ValueError(f"Non-positive or non-finite values: {protocol}, {n}")
                row[metric]=reduce(values)
                row[metric+"_run_min"]=min(values)
                row[metric+"_run_max"]=max(values)
            summary.append(row)
    if aggregation == "median" and audit is not None:
        # This companion must retain the previously delivered median results.
        old = {(r["protocol"],r["n"]):r for r in audit["repetition_medians"]}
        for row in summary:
            original = old[row["protocol"],row["n"]]
            if not math.isclose(row["throughput_outputs_per_second"],original["throughput_outputs_per_second"],rel_tol=1e-12):
                raise ValueError("Median plot disagrees with the delivered campaign summary")
    return rows,summary,inputs


def aligned_measurements(campaign,aggregation):
    settings=load(campaign/'campaign.json')['arguments']
    protocols=tuple(settings['protocols'].split(','));epochs=settings['epochs'];reps=settings['repetitions']
    sizes=[int(v) for v in settings['nodes'].split(',')]
    reduce=statistics.fmean if aggregation=='mean' else statistics.median
    rows=[];inputs={}
    for n in sizes:
        for series in protocols:
            protocol='asyrand' if series.startswith('asyrand') else series
            for rep in range(1,reps+1):
                cell=campaign/f'{series}-n{n}-r{rep}'
                report=load(cell/'validation.json');cfg=load(cell/'config.json');manifest=load(cell/'manifest.json')
                logs=[(cell/f'node{i}/stdout.log').read_text(encoding='utf-8') for i in range(n)]
                if not report['run_valid'] or not validate(logs,n,epochs,protocol)['run_valid']:
                    raise ValueError(f'invalid output sequence in {cell.name}')
                measured=generation_metrics(cell,n,epochs)
                if measured!=load(cell/'generation-metrics.json') or cfg['round']!=epochs:
                    raise ValueError(f'changed generation measurements in {cell.name}')
                final=load(cell/'containers-final.json')
                if len(final)!=n or any(c['State'].get('OOMKilled') for c in final):raise ValueError('invalid final container records')
                if not load(cell/'cleanup.json')['verified_terminated']:raise ValueError('cell was not cleaned up')
                row=dict(protocol=series,n=n,repetition=rep,emitted_outputs=epochs,
                    measured_intervals=measured['nodes'][0]['intervals'],measurement_scope=measured['scope'],
                    production_window=cfg.get('production_window',8) if protocol=='asyrand' else '',
                    adaptive_production_window=cfg.get('adaptive_production_window',False),
                    production_window_min=cfg.get('production_window_min','') if protocol=='asyrand' else '',
                    go_memory_limit=manifest['runtime_policy']['go_memory_limit'],recovery_interval_ms=cfg.get('recovery_interval_ms',1000))
                for metric in ('throughput_outputs_per_second','sent_kib_per_beacon_per_node','cpu_utilization_percent','cpu_ms_per_beacon','received_kib_per_beacon_per_node','memory_peak_mib','memory_end_mib'):
                    row[metric]=reduce(node[metric] for node in measured['nodes'])
                row['max_node_memory_mib']=max(node['memory_peak_mib'] for node in measured['nodes'])
                rows.append(row)
                paths=[cell/name for name in ('validation.json','config.json','manifest.json','containers-final.json','cleanup.json','generation-metrics.json')]
                paths += [cell/f'node{i}/{name}' for i in range(n) for name in ('measurement.jsonl','stdout.log')]
                for path in paths:inputs[str(path.resolve())]=sha(path)
    summary=[]
    metrics=('throughput_outputs_per_second','sent_kib_per_beacon_per_node','cpu_utilization_percent','cpu_ms_per_beacon','memory_peak_mib')
    for n in sizes:
        for series in protocols:
            selected=[row for row in rows if row['n']==n and row['protocol']==series]
            row=dict(protocol=series,n=n,runs=reps,aggregation=aggregation)
            for metric in metrics:
                values=[sample[metric] for sample in selected]
                if not all(math.isfinite(v) and v>0 for v in values):raise ValueError('invalid aligned metric')
                row[metric]=reduce(values);row[metric+'_run_min']=min(values);row[metric+'_run_max']=max(values)
            summary.append(row)
    return rows,summary,inputs,protocols


def draw(ax, summary, metric, title, unit, protocols=PROTOCOLS):
    for protocol in protocols:
        selected = [r for r in summary if r["protocol"] == protocol]
        label = "AsyRand W=8" if protocol == "asyrand" and "asyrand-w2" in protocols else DISPLAY[protocol]
        ax.plot([r["n"] for r in selected], [r[metric] for r in selected],
            label=label+("\u2020" if protocol.startswith("asyrand") else ""),
            color=COLORS[protocol],marker=MARKERS[protocol],linestyle=LINES[protocol],
            linewidth=1.45,markersize=3.8,markeredgecolor="white",markeredgewidth=0.45,zorder=3)
    ax.set(xlabel="Committee size $n$",ylabel=unit,title=title)
    ax.set_xticks(sorted({r['n'] for r in summary}))
    ax.margins(x=0.065,y=0.15)
    ax.set_ylim(bottom=0)
    if metric.startswith("cpu_"):
        ax.set_ylim(0,100)
    ax.yaxis.set_major_locator(MaxNLocator(nbins=5,min_n_ticks=3))
    ax.set_axisbelow(True)
    ax.grid(axis="y",color="#DEDEDE",linewidth=0.55)
    legend_location="lower right" if metric.startswith("cpu_") else ("upper right" if metric.startswith("throughput") else "upper left")
    ax.legend(loc=legend_location,handlelength=1.7,labelspacing=0.35)


def export(fig,stem):
    paths=[]
    for suffix in (".png",".pdf",".svg"):
        path=stem.with_suffix(suffix)
        fig.savefig(path,dpi=300)
        paths.append(path)
    plt.close(fig)
    return paths


def write_csv(path, rows):
    with path.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def runtime_note(runs):
    policies = {}
    for row in runs:
        if row["protocol"].startswith("asyrand"):
            policies.setdefault((row["recovery_interval_ms"],row["go_memory_limit"]),set()).add(row["n"])
    parts = []
    for (recovery,memory),nodes in sorted(policies.items()):
        if (recovery,memory) == (1000,"default"):
            continue
        where = "AsyRand" if nodes == set(NODES) else "AsyRand n="+",".join(map(str,sorted(nodes)))
        parts.append(f"{where}: recovery polling {recovery/1000:g} s; GOMEMLIMIT={memory}.")
    return "\u2020 "+" ".join(parts)+"  Network: 1 Gbit/s; one-way delay U(10, 30) ms."


def render(args):
    campaign=args.campaign.resolve()
    out=(args.output or campaign.parent/"figures").resolve()
    out.mkdir(parents=True,exist_ok=True)
    modern=(campaign/'campaign.json').exists() and load(campaign/'campaign.json')['arguments'].get('measure_generation',False)
    if modern:runs,summary,inputs,protocols=aligned_measurements(campaign,args.aggregation)
    else:runs,summary,inputs=measurements(campaign,args.aggregation);protocols=PROTOCOLS
    additional_campaigns={}
    if args.asyrand_w2_campaign:
        w2_campaign=args.asyrand_w2_campaign.resolve()
        w2_runs,w2_summary,w2_inputs=measurements(w2_campaign,args.aggregation,("asyrand",))
        if any(r["production_window"] != 2 for r in w2_runs):
            raise ValueError("Expected W=2 in every additional AsyRand cell")
        if any(r["production_window"] != 8 for r in runs if r["protocol"] == "asyrand"):
            raise ValueError("Expected W=8 in the original AsyRand cells")
        for row in w2_runs+w2_summary:
            row["protocol"]="asyrand-w2"
        runs+=w2_runs
        summary+=w2_summary
        inputs.update(w2_inputs)
        protocols=(*PROTOCOLS,"asyrand-w2")
        additional_campaigns["asyrand-w2"]=str(w2_campaign)
    aggregation_label="Arithmetic mean" if args.aggregation=="mean" else "Median"
    outputs=[]
    allocation=load(campaign/'campaign.json')['resources'] if modern else {}
    cores=allocation.get('cpu_cores_per_node',1)
    cpu_unit='CPU (% of 1 vCPU)' if cores==1 else f'CPU (% of {cores:g} vCPUs)'
    metrics=METRICS[:2]+(("cpu_utilization_percent","Online CPU utilization",cpu_unit),) if modern else METRICS
    policy=load(campaign/'campaign.json')['arguments'] if modern else {}
    crypto_cap=policy.get('crypto_cpu_percent',0)
    with plt.rc_context(STYLE):
        fig,axes=plt.subplots(1,3,figsize=(10.5,3.65 if crypto_cap else 3.4))
        for i,(metric,title,unit) in enumerate(metrics):
            draw(axes[i],summary,metric,f"({chr(97+i)}) {title}",unit,protocols)
        fig.subplots_adjust(left=0.06,right=0.99,bottom=0.36 if crypto_cap else 0.325,top=0.86,wspace=0.40)
        notes=[
            f"{aggregation_label} across nodes, then 3 runs.  200 outputs/node; 199 measured intervals.  1 vCPU / 2 GiB per node.",
            "Sent data = Tx frame bytes / 199 measured intervals per node; includes local self-delivery; excludes TLS/TCP.",
            "CPU: whole-container average including startup, verification and end waits; generation-window CPU was not recorded.",
            runtime_note(runs),
        ]
        if modern:
            epochs=runs[0]['emitted_outputs'];reps=summary[0]['runs']
            notes=[f'{aggregation_label} across nodes, then {reps} runs.  {epochs} outputs/node; {runs[0]["measured_intervals"]} measured intervals.  {cores:g} vCPU / {allocation["memory_mib_per_node"]/1024:g} GiB per node.',
                'Sent data = network Tx application-frame bytes per measured beacon; excludes self-delivery and TLS/TCP overhead.',
                f'CPU and traffic share {runs[0]["measurement_scope"]}; excludes initialization, offline verification and end waits.',runtime_note(runs)]
        if crypto_cap:
            notes.append(f'All protocols: GOMAXPROCS={policy["go_max_procs"]}; crypto workers={policy["crypto_workers"]}; proof partitions={policy["crypto_parallelism"]}; crypto-task cap={cores*crypto_cap/100:g} vCPU ({crypto_cap:g}% of node).')
        positions=(0.245,0.195,0.145,0.095,0.045) if crypto_cap else (0.195,0.15,0.105,0.06)
        for y,note in zip(positions,notes):
            fig.text(0.06,y,note,ha="left",va="center",fontsize=7,color="#606060")
        outputs += export(fig,out/"beacon-comparison")
    for name,rows in (("run-values.csv",runs),("summary-values.csv",summary)):
        path=out/name;write_csv(path,rows);outputs.append(path)
    references={}
    if args.silk_root:
        for name in ("code/experiments/plots/fig3.py","code/experiments/plots/bandwidth.py","paper/latex/figures/diagram-style.tex"):
            path=args.silk_root/name
            references[str(path.resolve())]=sha(path)
    manifest=dict(campaign=str(campaign),validated_runs=len(runs),validated_node_logs=sum(r["n"] for r in runs),
        additional_campaigns=additional_campaigns,plotted_series=list(protocols),
        committee_sizes=sorted({r['n'] for r in summary}),runs_per_cell=summary[0]['runs'],outputs_per_node=runs[0]['emitted_outputs'],measured_intervals=runs[0]['measured_intervals'],
        aggregation=f"{args.aggregation} across nodes within each run; {args.aggregation} of the three run values",
        plotted_metrics=[metric for metric, _, _ in metrics],
        communication_formula="final.sent_bytes / final.beacons / 2**10 per node; final.beacons=199; includes self-delivery; excludes TLS/TCP overhead",
        communication_caveat="Recorded application-frame sends include local self-delivery, which these logs cannot isolate. This is not an exact measure of inter-node-only sent data.",
        communication_aggregation="Normalize bytes by measured beacons separately for each node, then aggregate nodes and runs; do not divide aggregated bandwidth by aggregated throughput.",
        auxiliary_csv_metrics=["communication_kib_per_beacon_per_node", "bandwidth_mib_per_second"],
        auxiliary_communication_formula="Legacy CSV only: (final.sent_bytes + final.recv_bytes) / final.beacons / 2**10 per node",
        bandwidth_rate_formula="Auxiliary CSV only: (final.sent_bytes + final.recv_bytes) / final.elapsed_s / 2**20 per node",
        cpu_formula="cgroup cpu.stat usage_usec / 1e6 / (manifest.finished_at - Docker State.StartedAt) * 100 per node",
        cpu_caveat="Approximate whole-container average, including startup, verification and end waits; counter reads slightly precede the recorded completion timestamp. Not CPU utilization restricted to the beacon measurement window.",
        uncertainty="Run min/max retained in summary CSV; no error bars, matching Silk's current figures",
        runtime_note=runtime_note(runs),runtime_policy_note=notes[-1] if crypto_cap else None,style_references=references,protocol_colors=COLORS,
        render_script_sha256=sha(__file__),python=sys.version,matplotlib=matplotlib.__version__,
        inputs=inputs,outputs={str(p):sha(p) for p in outputs})
    if modern:
        manifest.update(communication_formula='network-only Tx frame byte delta / measured output intervals / 2**10 per node',
            communication_caveat='Excludes local self-delivery and TLS/TCP/IP overhead; not physical-link bytes.',
            cpu_formula=f'cgroup usage_usec delta / 1e6 / elapsed measured-window seconds / {cores:g} allocated vCPUs * 100 per node',
            cpu_caveat='Online generation window, with identical boundaries for CPU and network traffic.',
            auxiliary_csv_metrics=['cpu_ms_per_beacon','memory_peak_mib'],measurement_scope=runs[0]['measurement_scope'])
        manifest.pop('auxiliary_communication_formula',None)
        manifest.pop('bandwidth_rate_formula',None)
    (out/"plot-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(out/"beacon-comparison.png")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("campaign",type=Path)
    p.add_argument("--aggregation",choices=("mean","median"),default="mean")
    p.add_argument("--output",type=Path)
    p.add_argument("--silk-root",type=Path)
    p.add_argument("--asyrand-w2-campaign",type=Path,
                   help="Additional AsyRand W=2 campaign; retain W=8 and both baselines")
    render(p.parse_args())


if __name__=="__main__":
    main()
