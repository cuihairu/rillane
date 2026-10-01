#!/usr/bin/env python3
"""P1-5 §0.2 出站连接池验收统计脚本。

从 seepd 控制面 /metrics 抓取 seep_pool_* / seep_tls_* 序列，按
egress-connection-pool.md §0.2 三判据输出验收结论。纯标准库，无第三方依赖。

三组数（§0.2 口径注记：避免"握手下降"歧义，显式分组输出）：
  ① 前台握手   = seep_pool_dials_total{origin="foreground",result="ok"}
                 ——请求路径阻塞拨号/握手次数；命中借出的请求零拨号（判据 2 可测口径）
  ② 恢复占比   = seep_tls_handshakes_total{type="resumed"} /
                 seep_tls_handshakes_total{type=*}
                 ——预热/补充拨号的握手被会话恢复（HandshakeKind::Resumed）取代的占比
  ③ 总拨号     = seep_pool_dials_total{origin=*,result="ok"} 之和
                 ——≈ 流数不降（每流消耗一条连接的结构约束，§1.2；真降需 V2 多路复用）

判据（--requests N，默认 10）：
  1. seep_pool_acquires_total{result="hit"} ≥ N−1（装配预热后 miss 可为 0）
  2. seep_pool_reuse_ratio ≥ (N−1)/N
  3. 前台握手 ≤ 1

用法：
    python3 scripts/pool_reuse_stats.py --url http://127.0.0.1:9090/metrics
    python3 scripts/pool_reuse_stats.py --requests 20 --url ...
    cat metrics.txt | python3 scripts/pool_reuse_stats.py --in -
    python3 scripts/pool_reuse_stats.py --in metrics.txt

退出码：0 = 三判据全过；1 = 有判据未过；2 = 输入缺 seep_pool_* 序列
（池未启用——§8.2 关闭态对照即此形，非采集错误）。
"""

import argparse
import json
import re
import sys
import urllib.request

SERIES_RE = re.compile(
    r"^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+(?P<value>[0-9.eE+%-]+)$"
)

LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"')


def parse_metrics(text: str) -> dict:
    """Prometheus 文本格式 → {(name, frozenset(labels)): value}。"""
    series = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = SERIES_RE.match(line)
        if not m:
            continue
        labels = frozenset(LABEL_RE.findall(m.group("labels") or ""))
        try:
            value = float(m.group("value"))
        except ValueError:
            continue
        series[(m.group("name"), labels)] = value
    return series


def get(series: dict, name: str, **labels) -> float:
    key = (name, frozenset(labels.items()))
    return series.get(key, 0.0)


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="P1-5 出站连接池验收统计（§0.2）")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="控制面 /metrics 地址")
    src.add_argument("--in", dest="infile", help="metrics 文本文件路径，- = stdin")
    ap.add_argument("--requests", type=int, default=10,
                    help="验收串行请求数 N（判据阈值 N−1，默认 10）")
    args = ap.parse_args()

    if args.url:
        text = fetch(args.url)
    elif args.infile == "-":
        text = sys.stdin.read()
    else:
        with open(args.infile, encoding="utf-8") as f:
            text = f.read()

    series = parse_metrics(text)
    if not any(name.startswith("seep_pool_") for name, _ in series):
        print("输入无 seep_pool_* 序列：出站连接池未启用（无 egress_pool 块时"
              "/metrics 不渲染该族，§8.2 关闭态对照形）", file=sys.stderr)
        return 2

    n = args.requests
    threshold_ratio = (n - 1) / n

    # ---- 三组数（§0.2 口径注记）------------------------------------------
    hit = get(series, "seep_pool_acquires_total", result="hit")
    miss = get(series, "seep_pool_acquires_total", result="miss")
    stale = get(series, "seep_pool_acquires_total", result="stale_redial")
    fg_ok = get(series, "seep_pool_dials_total", origin="foreground", result="ok")
    fg_err = get(series, "seep_pool_dials_total", origin="foreground", result="error")
    warm_ok = get(series, "seep_pool_dials_total", origin="warm", result="ok")
    refill_ok = get(series, "seep_pool_dials_total", origin="refill", result="ok")
    total_dials = fg_ok + fg_err + warm_ok + refill_ok
    reuse_gauge = get(series, "seep_pool_reuse_ratio")
    h_full = get(series, "seep_tls_handshakes_total", type="full")
    h_hrr = get(series, "seep_tls_handshakes_total", type="full_hrr")
    h_resumed = get(series, "seep_tls_handshakes_total", type="resumed")
    h_all = h_full + h_hrr + h_resumed
    resumed_ratio = h_resumed / h_all if h_all > 0 else 0.0

    # 复用率双源：gauge 在则用 gauge，否则按计数现算（口径一致 = hit/(hit+miss)）
    if reuse_gauge > 0:
        reuse = reuse_gauge
    elif hit + miss > 0:
        reuse = hit / (hit + miss)
    else:
        reuse = 0.0

    print("=" * 64)
    print("P1-5 出站连接池验收统计（egress-connection-pool.md §0.2）")
    print("=" * 64)
    print(f"① 前台握手   seep_pool_dials_total{{origin=foreground}} ok={fg_ok:.0f} err={fg_err:.0f}")
    print(f"   恢复占比   seep_tls_handshakes_total resumed={h_resumed:.0f}/all={h_all:.0f}"
          f" = {resumed_ratio * 100:.1f}%  (full={h_full:.0f} full_hrr={h_hrr:.0f})")
    print(f"③ 总拨号     seep_pool_dials_total ok 之和 = {total_dials:.0f}"
          f"  (fg={fg_ok:.0f} warm={warm_ok:.0f} refill={refill_ok:.0f}；≈流数不降，§1.2)")
    print("-" * 64)
    print(f"acquires hit={hit:.0f} miss={miss:.0f} stale_redial={stale:.0f}"
          f"  reuse_ratio={reuse:.3f}")

    verdicts = [
        (f"判据1 hit≥{n - 1}", hit >= n - 1),
        (f"判据2 reuse_ratio≥{threshold_ratio:.2f}", reuse >= threshold_ratio),
        ("判据3 前台握手≤1", fg_ok <= 1),
    ]
    ok = True
    for label, passed in verdicts:
        mark = "PASS" if passed else "FAIL"
        ok = ok and passed
        print(f"  [{mark}] {label}")
    print("=" * 64)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
