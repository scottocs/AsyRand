#!/usr/bin/env python3
"""Summarize latest_compare.py results and export standalone scientific plots."""
import argparse
import csv
import html
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile

sys.dont_write_bytecode = True

VARIANTS = ("asyrand-standard", "asyrand-parallel", "grandline", "spurt")
LABELS = {"asyrand-standard": "AsyRand standard", "asyrand-parallel": "AsyRand parallel",
          "grandline": "GRandLine", "spurt": "SPURT"}


def read_csv(path):
    with path.open() as stream:
        return list(csv.DictReader(stream))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    environment = json.loads((out/"environment.json").read_text())
    validation = json.loads((out/"validation.json").read_text())
    rows, summary = read_csv(out/"results.csv"), read_csv(out/"summary.csv")
    variants = tuple(v for v in VARIANTS if v in environment["variants"])
    nodes = environment["nodes"]
    if validation["successful_runs"] != validation["expected_runs"] or len(rows) != validation["expected_runs"]:
        raise RuntimeError("incomplete experiment; do not generate a complete report")
    table = {(r["variant"], int(r["nodes"])): r for r in summary}

    def fmt(variant, n, metric):
        r = table[(variant, n)]
        if r["mean_"+metric] == "": return "—"
        return f'{float(r["mean_"+metric]):.2f} ± {float(r["stdev_"+metric]):.2f}'

    lines = ["最新本地实现对比：AsyRand、GRandLine、SPURT", "",
             f'环境：{environment.get("cpu", environment["platform"])}, {environment["target_goarch"]}, '
             f'{environment.get("memory_bytes", 0)/2**30:.0f} GiB；{environment["go"]}。',
             '被测二进制的目标架构：'+environment['target_goarch']+'；Go 工具的架构标记不等于目标架构。',
             '单机 memory transport，GOMAXPROCS=8，每节点 4 个密码学工作线程；逐项串行测量并轮换顺序。',
             f'每组 {environment["repeats"]} 次；预热 {environment["warmup_outputs"]} 个输出后，'
             f'测量 {environment["measured_intervals"]} 个输出间隔；下表为均值 ± 样本标准差。',
             'setup、3 秒 prefill、结束后的独立公开验证均不计入吞吐时间。未注入故障。',
             '通信量是同一后预热窗口内全委员会发送字节/输出数，包含 loopback，不叠加接收字节。',
             '吞吐计时：'+environment.get("throughput_clock", "UTC 输出日志首末时间差（旧版统计方式）")+'。',
             '', '吞吐量（全局 beacon/s）',
             '实现\t'+'\t'.join(f'n={n}' for n in nodes)]
    for variant in variants:
        lines.append(LABELS[variant]+'\t'+'\t'.join(fmt(variant, n, "beacon_s") for n in nodes))
    lines += ['', '通信量（全委员会 KiB/beacon，后预热窗口）',
              '实现\t'+'\t'.join(f'n={n}' for n in nodes)]
    for variant in variants:
        lines.append(LABELS[variant]+'\t'+'\t'.join(fmt(variant, n, "post_sent_kib_per_beacon") for n in nodes))
    lines += ['', '输出间隔（ms；各次运行的分位数再取均值 ± 样本标准差）', '节点\t实现\tp50\tp95']
    for n in nodes:
        for variant in variants:
            lines.append(f'{n}\t{LABELS[variant]}\t{fmt(variant,n,"p50_interval_ms")}\t{fmt(variant,n,"p95_interval_ms")}')
    if "asyrand-standard" in variants and "asyrand-parallel" in variants:
        lines += ['', 'AsyRand 模式对比（parallel 相对 standard 的运行均值）']
        for n in nodes:
            a, b = table[("asyrand-standard", n)], table[("asyrand-parallel", n)]
            speed = float(b["mean_beacon_s"])/float(a["mean_beacon_s"])-1
            traffic = float(b["mean_post_sent_kib_per_beacon"])/float(a["mean_post_sent_kib_per_beacon"])-1
            lines.append(f'n={n}: 吞吐 {speed:+.2%}，通信 {traffic:+.2%}')
    comparisons = []
    if "asyrand-parallel" in variants:
        lines += ['', 'AsyRand parallel 相对同批次其他协议（均值之比）']
        for n in nodes:
            a = table[("asyrand-parallel", n)]
            for variant in (v for v in variants if v in ("grandline", "spurt")):
                b = table[(variant, n)]
                speed = float(a["mean_beacon_s"])/float(b["mean_beacon_s"])
                traffic = float(a["mean_post_sent_kib_per_beacon"])/float(b["mean_post_sent_kib_per_beacon"])-1
                comparisons.append(dict(nodes=n, baseline=variant, asyrand_parallel_speed_ratio=speed,
                                        asyrand_parallel_traffic_relative_change=traffic))
                lines.append(f'n={n} vs {LABELS[variant]}: 吞吐 {speed:.2f} 倍，通信 {traffic:+.2%}')
    if comparisons:
        from parallel_stats import write_csv
        write_csv(out/"relative_comparison.csv", comparisons)
    lines += ['', '解释范围与实现差异',
              'AsyRand 两种模式均使用 ALBATROSS；standard 在当前列第一个重构份额前等待下一列决定，',
              'parallel 允许当前列前 f 个输出与下一列 ABA 重叠，第 f+1 个份额释放前仍必须等待下一列。',
              'standard 对应当前论文正文的屏障规则；parallel 是本地代码的重叠变体，性能测试不构成其独立安全证明。',
              '本轮运行模式：'+', '.join(LABELS[v] for v in variants)+'。',
              '本轮签名策略（读取实验存档元数据，不按当前源码推断）：',
              *[f'{name}: {policy}' for name, policy in environment["ordinary_signatures"].items()],
              '数值包含各自认证、原生证明与证书的实现开销，不能将差距全部归因于协议结构。',
              '三者均缓存节点内部成功验证结果；不同节点和独立公开验证器不共享缓存。',
              'GRandLine 每个输出仍需原生 DLEQ、pairing、GT 子群检查和 GT 插值；DKG 只摊销密钥生成。',
              '本地 kilic v0.1.0 的 arm64 构建使用通用域算术，并非 ARM 专用密码汇编。',
              '所有节点共用同一进程的 GOMAXPROCS=8，节点增加时总 CPU 预算没有增加。',
              '吞吐率是端到端指标，不等于纯密码学 CPU 时间；并发操作计时也不能直接相加为输出延迟。',
              'GRandLine 使用论文实验式模拟 setup；SPURT 尚无完整 HotStuff 换视图。',
              '这是当前 Go/kilic/JSON 实现的单机正常路径结果，不是 WAN、完整容错或论文原始性能复现。',
              'f 分别为 1/2/5；AsyRand 证书和 SPURT 投票阈值均为 n-f，重构阈值均为 f+1。',
              'SPURT 对非紧配置使用 n-f，并恢复 f+1 FINALIZE 放大；无故障测试不等于完整容错验证。',
              f'每组 {environment["repeats"]} 次，勿将均值差异当作显著性结论。',
              'GRandLine 本轮模式：'+environment.get("grandline_beacon_mode", "见存档配置")+'。',
              'UTC 时间异常的日志：'+(', '.join(validation.get("suspect_utc_logs", [])) or '无')+'；异常轮次的 UTC 分位数不参与汇总。',
              '', '验证与保存内容',
              f'{validation["successful_runs"]} 组均完成连续输出并检查所有节点输出一致；',
              f'AsyRand 共 {validation["public_verified_asyrand_epochs"]:,} 个全局输出通过独立公开历史验证。',
              'results.csv：逐次原始结果；summary.csv：均值和样本标准差；runner_metrics.csv：完整 runner 指标。',
              'environment.json：环境、配置口径、源码和二进制哈希；validation.json：完整性校验。',
              'sources.tar.gz、bin/：源码快照和实际二进制；*.json、*.log、*.history.json：配置、日志和公开历史。',
              'relative_comparison.csv：同批次 AsyRand parallel 相对其他协议的吞吐及通信比值。',
              '旧实验结果和论文文件均未覆盖。', '', '复现命令（使用一个新的输出目录）',
              'python3 asyrand/benchmarks/latest_compare.py --out <新目录> --variants '+' '.join(variants)+' --nodes '+' '.join(map(str,nodes))+f' --repeats {environment["repeats"]} --warmup {environment["warmup_outputs"]} --intervals {environment["measured_intervals"]}',
              'python3 asyrand/benchmarks/latest_report.py <新目录>']
    report = '\n'.join(lines)+'\n'
    (out/"report.txt").write_text(report)
    os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir())/"tyche-latest-mpl"))
    os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir())/"tyche-latest-cache"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    colors = {"asyrand-standard":"#5b7083", "asyrand-parallel":"#2676b9", "grandline":"#21865b", "spurt":"#c67a20"}
    fig, axes = plt.subplots(1, 2, figsize=(11.8, 4.5), layout="constrained")
    for ax, metric, label in zip(axes, ("beacon_s", "post_sent_kib_per_beacon"),
                                 ("Throughput (global beacon/s)", "Committee sent traffic (KiB/beacon)")):
        for variant in variants:
            mean = [float(table[(variant,n)]["mean_"+metric]) for n in nodes]
            sd = [float(table[(variant,n)]["stdev_"+metric]) for n in nodes]
            ax.errorbar(nodes, mean, yerr=sd, label=LABELS[variant], color=colors[variant],
                        marker="o", capsize=4, linewidth=1.8)
        ax.set_xticks(nodes)
        ax.set_xlabel("Committee size n")
        ax.set_ylabel(label)
        if metric == "beacon_s":
            ax.set_yscale("log")
            ax.set_ylabel(label+" (log scale)")
        else:
            ax.set_ylim(bottom=0)
        ax.grid(alpha=.2)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].legend(frameon=False)
    fig.suptitle(f'Current local implementations · {environment.get("cpu", environment["platform"])} / {environment["target_goarch"]} · {environment["repeats"]} runs, mean ± sample SD\n'
                 f'{environment["warmup_outputs"]} warm-up outputs + {environment["measured_intervals"]} measured intervals; '+('monotonic throughput' if 'throughput_clock' in environment else 'UTC log timing'), fontsize=11)
    fig.savefig(out/"comparison.svg")
    fig.savefig(out/"comparison.png", dpi=180)
    plt.close(fig)
    (out/"report.html").write_text('<!doctype html><html lang="zh"><meta charset="utf-8">'
                                 '<title>最新协议对比</title><style>body{max-width:1200px;margin:32px auto;'
                                 'font:16px/1.65 system-ui;padding:0 20px}img{width:100%}'
                                 'pre{white-space:pre-wrap;font:14px/1.7 system-ui}</style>'
                                 '<img src="comparison.svg" alt="吞吐量与通信量比较">'
                                 '<pre>'+html.escape(report)+'</pre></html>')
    print(report)


if __name__ == "__main__":
    main()
