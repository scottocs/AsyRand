#!/usr/bin/env python3
"""Report throughput, sent rate and an audited AsyRand producer/consumer split."""
import argparse
import csv
import html
import json
import os
from pathlib import Path
import shutil
import statistics
import sys

sys.dont_write_bytecode = True
from parallel_stats import write_csv
from traffic_breakdown import PARTS

LABELS = {"asyrand-parallel": "AsyRand parallel", "grandline": "GRandLine", "spurt": "SPURT"}
COMPONENTS = {"producer":"Producer / RBC", "aba_core":"ABA core", "aba_certificate":"ABA certificates",
              "aba_recovery":"ABA SYNC / REPLAY", "reconstruction":"Consumer / RECON", "history_recovery":"Consumer / history"}


def read_csv(path):
    with path.open() as stream: return list(csv.DictReader(stream))


def stats(values):
    return statistics.mean(values), statistics.stdev(values) if len(values)>1 else 0


def cell(mean, sd): return f"{mean:.2f} ± {sd:.2f}"


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out",type=Path)
    args=ap.parse_args();out=args.out.resolve()
    env=json.loads((out/"environment.json").read_text())
    valid=json.loads((out/"validation.json").read_text())
    if valid["successful_runs"]!=valid["expected_runs"]: raise RuntimeError("incomplete experiment")
    runs=read_csv(out/"results.csv");traffic=read_csv(out/"asyrand_traffic.csv")
    nodes=env["nodes"];variants=env["variants"]
    bw=[];groups=[]
    for n in nodes:
        for variant in variants:
            sample=[r for r in runs if r["variant"]==variant and int(r["nodes"])==n]
            if len(sample)!=env["repeats"]: raise RuntimeError("missing repeated run")
            row=dict(nodes=n,protocol=variant,repeats=len(sample))
            for metric in ("beacon_s","post_sent_mib_s","post_sent_kib_s","post_sent_kib_per_beacon"):
                row["mean_"+metric],row["stdev_"+metric]=stats([float(r[metric]) for r in sample])
            row["mean_per_node_sent_mib_s"]=row["mean_post_sent_mib_s"]/n
            bw.append(row)
        for window in ("final","run"):
            for category in (*PARTS,"aba","consumer","total"):
                sample=[r for r in traffic if int(r["nodes"])==n and r["window"]==window and r["category"]==category]
                row=dict(nodes=n,window=window,category=category,repeats=len(sample))
                if len(sample)!=env["repeats"]: raise RuntimeError("missing classified run")
                for metric in ("sent_mib_s","sent_kib_s","sent_kib_per_beacon","pct_of_total"):
                    row["mean_"+metric],row["stdev_"+metric]=stats([float(r[metric]) for r in sample])
                total=sum(int(r["sent_bytes"]) for r in traffic if int(r["nodes"])==n and r["window"]==window and r["category"]=="total")
                row["pooled_pct_of_total"]=100*sum(int(r["sent_bytes"]) for r in sample)/total
                groups.append(row)
    write_csv(out/"bandwidth_summary.csv",bw)
    write_csv(out/"asyrand_traffic_summary.csv",groups)
    b={(r["protocol"],r["nodes"]):r for r in bw}
    g={(r["nodes"],r["window"],r["category"]):r for r in groups}
    for n in nodes:
        assert abs(g[n,"final","producer"]["mean_pct_of_total"]+g[n,"final","consumer"]["mean_pct_of_total"]-100)<1e-9
        assert abs(sum(g[n,"final",c]["mean_pct_of_total"] for c in PARTS)-100)<1e-9

    lines=["本地 4/8/16 节点吞吐、带宽及 AsyRand 流量构成", "",
           f"AsyRand 仅 parallel。目标架构 {env['target_goarch']} / {env.get('cpu',env['platform'])}，memory，GOMAXPROCS={env['gomaxprocs']}，每节点 {env['workers_per_node']} 个 crypto worker。",
           f"每组 {env['repeats']} 次；每次 {env['warmup_outputs']+env['measured_intervals']+1} 个全局输出，前 {env['warmup_outputs']} 个预热，随后 {env['measured_intervals']} 个输出间隔用于测量。",
           "f=1/2/5，重构门限=2/3/6；AsyRand production_window=8，SPURT lookahead=8；逐项串行并轮换顺序。",
           "以下为每次运行指标的均值 ± 样本标准差。吞吐与速率使用 Go 单调时钟。",
           "带宽=测量窗口内委员会发送字节/时间，包含 loopback，不叠加接收，不是链路容量；1 MiB=1024 KiB。",
           "setup、3s prefill 和独立公开验证不计入测量。另给 KiB/beacon，区分发送速率与每输出通信开销。", "",
           "1. 各协议吞吐率与发送带宽", "节点 | 协议 | beacon/s | 委员会 MiB/s | 平均每节点 MiB/s | KiB/beacon"]
    table=[]
    for n in nodes:
        for variant in variants:
            r=b[variant,n]
            row=[str(n),LABELS[variant],cell(r['mean_beacon_s'],r['stdev_beacon_s']),
                 cell(r['mean_post_sent_mib_s'],r['stdev_post_sent_mib_s']),f"{r['mean_per_node_sent_mib_s']:.3f}",
                 cell(r['mean_post_sent_kib_per_beacon'],r['stdev_post_sent_kib_per_beacon'])]
            table.append(row);lines.append(" | ".join(row))
    lines += ["", "2/3. AsyRand ABA、producer 与 consumer 占比", "节点 | producer % | consumer % | ABA %（consumer 子集） | 历史恢复 %（consumer 子集）"]
    shares=[]
    for n in nodes:
        vals=[g[n,"final",c] for c in ("producer","consumer","aba","history_recovery")]
        row=[str(n)]+[cell(r['mean_pct_of_total'],r['stdev_pct_of_total']) for r in vals]
        shares.append(row);lines.append(" | ".join(row))
    lines += ["", "AsyRand 分类发送速率（委员会 MiB/s，均值）", "节点 | producer | consumer | ABA | RECON | 历史恢复"]
    for n in nodes: lines.append(" | ".join([str(n)]+[f"{g[n,'final',c]['mean_sent_mib_s']:.3f}" for c in ("producer","consumer","aba","reconstruction","history_recovery")]))
    lines += ["", "占比口径", "producer = PVSS 对象的 RBC 分发：VAL/ECHO/READY/REQUEST/REPLY。",
              "consumer = ABA 协议 + 重构 RECON + 历史恢复 HISTORY/REPLY；ABA 是 consumer 子集，不能再次相加。",
              "ABA = PRE/VOTE/MAIN/FINAL + DECISION/CERT_REQUEST/CERT_RESPONSE + SYNC/REPLAY。",
              "HISTORY/REPLY 可能携带列证据和 ABA/RBC 证书，统一按恢复用途计入 consumer，并单列历史恢复；未按嵌入载荷拆分。",
              "因此 ABA 比例表示可直接归属 ABA 消息的带宽，不含历史回复中嵌入证据的重复传输。",
              "比例按同一测量窗口内完整序列化消息的发送字节计算；producer+consumer=100%，所有分类与总计数精确对账。",
              "统计文件同时给出逐次比例均值/标准差与跨次按字节加权比例；正文采用逐次比例均值。",
              "producer 与 consumer 并发运行，生产窗口为 W=8；这些是给定测量窗口的实际流量份额，不是静态理论比例。", "",
              "校验与范围",f"{valid['successful_runs']} 次运行完成，所有节点输出一致；AsyRand {valid['public_verified_asyrand_epochs']} 个输出通过独立公开验证。",
              "GRandLine、SPURT 普通外层签名计数均为零，原生证明和签名验证保留；缓存仅在单节点内部复用。",
              "GRandLine 使用 standard 模式（一次在线 COMMIT），离线 APVSS setup 不计入吞吐；完整递归 DKG 和 SPURT 完整换视图未实现。",
              "这是单机无故障正常路径测量，不是 WAN 或论文原始性能复现；协议代码与论文在测量期间保持不变。",
              "UTC 时间异常（仅影响相应分位数，吞吐使用单调时钟）："+(', '.join(valid['suspect_utc_logs']) or '无'), "",
              "数据文件：bandwidth_summary.csv、asyrand_traffic_summary.csv、asyrand_traffic.csv、message_types.csv、results.csv、runner_metrics.csv。",
              "environment.json、validation.json、sources.tar.gz、bin/、配置、日志和公开历史均已保存。"]
    report="\n".join(lines)+"\n";(out/"bandwidth_report.txt").write_text(report)

    os.environ.setdefault("MPLCONFIGDIR","/private/tmp/tyche-bandwidth-mpl")
    os.environ.setdefault("XDG_CACHE_HOME","/private/tmp/tyche-bandwidth-cache")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    colors={"asyrand-parallel":"#2563eb","grandline":"#059669","spurt":"#d97706"}
    fig,axes=plt.subplots(1,2,figsize=(11,4.3),layout="constrained")
    for ax,metric,title in zip(axes,("beacon_s","post_sent_mib_s"),("Throughput (beacon/s)","Committee sent rate (MiB/s)")):
        for v in variants:
            ax.errorbar(nodes,[b[v,n]['mean_'+metric] for n in nodes],yerr=[b[v,n]['stdev_'+metric] for n in nodes],label=LABELS[v],color=colors[v],marker="o",capsize=4)
        ax.set_xticks(nodes);ax.set_xlabel("Nodes");ax.set_ylabel(title);ax.grid(alpha=.2);ax.spines[['top','right']].set_visible(False)
    axes[0].set_yscale('log');axes[0].set_ylabel('Throughput (beacon/s, log scale)');axes[0].legend(frameon=False)
    axes[1].set_ylim(bottom=0)
    fig.suptitle(f"Same-batch comparison · {env['repeats']} runs, mean ± sample SD · monotonic time")
    fig.savefig(out/"bandwidth_comparison.png",dpi=180);fig.savefig(out/"bandwidth_comparison.svg");plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4.8),layout="constrained")
    bottoms=[0.0]*len(nodes);palette=("#2563eb","#7c3aed","#c4b5fd","#f59e0b","#059669","#64748b")
    for c,color in zip(PARTS,palette):
        values=[g[n,"final",c]['mean_pct_of_total'] for n in nodes]
        ax.bar(range(len(nodes)),values,bottom=bottoms,color=color,label=COMPONENTS[c])
        bottoms=[a+v for a,v in zip(bottoms,values)]
    ax.set_xticks(range(len(nodes)),nodes);ax.set(ylim=(0,100),xlabel="Nodes",ylabel="Committee sent bytes (%)",title="AsyRand parallel: traffic by protocol function")
    ax.legend(loc='upper center',bbox_to_anchor=(.5,-.14),ncol=3,frameon=False,fontsize=9);ax.spines[['top','right']].set_visible(False)
    fig.savefig(out/"asyrand_traffic.png",dpi=180);fig.savefig(out/"asyrand_traffic.svg");plt.close(fig)
    def html_table(headers,body):
        return '<table><tr>'+''.join('<th>'+html.escape(x)+'</th>' for x in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+html.escape(x)+'</td>' for x in row)+'</tr>' for row in body)+'</table>'
    page='<!doctype html><meta charset="utf-8"><title>协议性能与 AsyRand 带宽构成</title><style>body{font:16px/1.6 system-ui;max-width:1200px;margin:32px auto;padding:0 20px;color:#172033}table{border-collapse:collapse;width:100%;margin:20px 0}td,th{padding:8px;text-align:right;border-bottom:1px solid #ddd}img{width:100%}pre{white-space:pre-wrap;font:14px/1.8 system-ui}</style><h1>协议性能与 AsyRand 带宽构成</h1>'
    page+=html_table(['节点','协议','beacon/s','委员会 MiB/s','平均每节点 MiB/s','KiB/beacon'],table)
    page+='<img src="bandwidth_comparison.svg" alt="吞吐与发送带宽">'+html_table(['节点','producer %','consumer %','ABA %（consumer 子集）','历史恢复 %'],shares)
    page+='<img src="asyrand_traffic.svg" alt="AsyRand 流量构成"><pre>'+html.escape(report)+'</pre>'
    (out/"bandwidth_report.html").write_text(page)
    shutil.copy2(Path(__file__),out/Path(__file__).name)
    print(report)


if __name__=="__main__":main()
