#!/usr/bin/env python3
"""P1-4 §7.2 padding 帧长分布检查脚本。

对采集到的 seepd mesh 数据面流量做 header 帧长分布统计，验证 padding 已
实际生效（分布偏离"未开启 = 帧长恒等于明文 header 长度"的单点形，
obfuscation-middleware.md §0/§7.2）。纯标准库，无第三方依赖。

线格式（mesh_transport.rs MeshEnvelope，TCP mesh 数据面前导帧）：
    [u32 大端 N][N 字节 = header JSON（version/flow_id/target_host/
    target_port/path[/pad_len]） + pad_len 个 0x00 填充]
填充帧 version=2 且 pad_len>0；未填充帧与旧行为字节一致（version=1、
无 pad_len 字段）。载荷在帧后另行流转，故解析采用扫描式：逐偏移试探
[u32][严格 JSON + 尾零] 帧，命中后跳到帧尾继续。

用法：
    # ① raw 模式：tcpdump/socat 落地的字节流（TCP 流或 datagram 拼接均可）
    python3 scripts/obfs_padding_dist.py raw capture.bin --require-padding

    # ② pcap 模式：libpcap 文件（自动抽 TCP/UDP 载荷拼接后扫描；
    #    跨包截断的帧会被跳过——对分布判定是可容忍的漏采）
    python3 scripts/obfs_padding_dist.py pcap capture.pcap

    # ③ stdin：tcpdump -w - | ... 或 socat -u TCP-LISTEN:... -
    cat capture.bin | python3 scripts/obfs_padding_dist.py raw -

输出：帧长直方图（min/p50/p90/p99/max/mean + 逐长度计数）+ 填充帧占比。
判定：--require-padding 时，解析到帧但 pad_len>0 占比为 0 → 退出码 1
（§7.2 关闭态对照形：分布未偏离默认）；无帧退出码 2。
"""

import argparse
import json
import math
import struct
import sys
from collections import Counter

REQUIRED_FIELDS = {"version", "flow_id", "target_host", "target_port", "path"}


def try_frame(data: bytes, off: int):
    """在 data[off:] 试探一帧；返回 (声明帧长 N, meta, 错误信息) 或 None。"""
    if off + 4 > len(data):
        return None
    (n,) = struct.unpack_from(">I", data, off)
    if n < 2 or n > 65536 or off + 4 + n > len(data):
        return None
    body = data[off + 4 : off + 4 + n]
    # 找 JSON 尾（填充为 0x00 尾零；JSON 本身不以 0x00 结尾）
    json_end = n
    while json_end > 0 and body[json_end - 1] == 0:
        json_end -= 1
    pad_len = n - json_end
    try:
        meta = json.loads(body[:json_end].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(meta, dict) or not REQUIRED_FIELDS.issubset(meta):
        return None
    declared_pad = int(meta.get("pad_len", 0))
    if declared_pad != pad_len:
        return meta, n, f"E7 校验失败：声明 pad_len={declared_pad} 尾零实为 {pad_len}"
    if declared_pad > 0 and int(meta["version"]) < 2:
        return meta, n, f"E7 校验失败：version={meta['version']} 却带填充（旧端拒绝口径）"
    return meta, n, None


def scan_frames(data: bytes):
    """扫描式全帧提取：命中后跳帧尾，失配则前进 1 字节重试。"""
    frames, warnings = [], []
    off = 0
    while off + 6 <= len(data):
        hit = try_frame(data, off)
        if hit is None:
            off += 1
            continue
        meta, n, warn = hit
        if warn:
            warnings.append(warn)
        frames.append((meta, n))
        off += 4 + n
    return frames, warnings


def extract_pcap_payloads(data: bytes):
    """libpcap 全局头 + 记录头逐包抽 TCP/UDP 载荷，拼接为一个扫描缓冲。"""
    if len(data) < 24:
        return b""
    magic = data[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        print("错误：非 libpcap 魔数", file=sys.stderr)
        return b""
    out = []
    off = 24
    n = len(data)
    while off + 16 <= n:
        _, _, caplen, _ = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkt = data[off : off + caplen]
        off += caplen
        payload = extract_l4_payload(pkt)
        if payload:
            out.append(payload)
    return b"".join(out)


def extract_l4_payload(pkt: bytes):
    """Ethernet 或裸 IP → IPv4/IPv6 → TCP/UDP 载荷；无法解析返回 b""。"""
    if len(pkt) < 40:
        return b""
    l3 = 14
    if pkt[0] >> 4 in (4, 6):
        l3 = 0  # 裸 IP（无链路层头）
    else:
        ethertype = struct.unpack_from(">H", pkt, 12)[0]
        if ethertype not in (0x0800, 0x86DD):
            return b""
    ver = pkt[l3] >> 4
    if ver == 4:
        ihl = (pkt[l3] & 0x0F) * 4
        proto = pkt[l3 + 9]
        l4 = l3 + ihl
    elif ver == 6:
        proto = pkt[l3 + 6]
        l4 = l3 + 40
    else:
        return b""
    if proto not in (6, 17) or len(pkt) <= l4:
        return b""
    return pkt[l4:]


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = max(0, min(len(sorted_vals) - 1, math.ceil(p / 100 * len(sorted_vals)) - 1))
    return sorted_vals[k]


def report(frames, require_padding):
    padded = sum(1 for (m, _) in frames if int(m.get("pad_len", 0)) > 0)
    print(f"帧数：{len(frames)}（填充帧 pad_len>0：{padded}，占比 {padded / len(frames):.1%}）")
    lens = sorted(n for (_, n) in frames)
    print(
        f"帧长：min={lens[0]} p50={percentile(lens, 50)} p90={percentile(lens, 90)} "
        f"p99={percentile(lens, 99)} max={lens[-1]} mean={sum(lens) / len(lens):.1f}"
    )
    hist = Counter(lens)
    print("直方图（帧长 × 计数）：")
    for length in sorted(hist):
        print(f"  {length:>6}  {hist[length]:>6}  {'#' * min(60, hist[length])}")
    print(f"不同帧长取值：{len(hist)}")
    if len(hist) == 1 and padded == 0:
        print("提示：单点分布且零填充——§7.2 关闭态对照形（padding 未生效）")
    if require_padding and padded == 0:
        print("判定失败：--require-padding 但填充帧占比 0（分布未偏离默认形）")
        return 1
    print("判定通过：填充帧已现，分布数据如上")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("mode", choices=["raw", "pcap"], help="输入格式")
    ap.add_argument("input", help="文件路径，或 - 表示 stdin")
    ap.add_argument(
        "--require-padding",
        action="store_true",
        help="判定模式：解析到帧但填充帧占比 0 时退出码 1（§7.2 验收）",
    )
    args = ap.parse_args()

    data = sys.stdin.buffer.read() if args.input == "-" else open(args.input, "rb").read()
    if args.mode == "pcap":
        data = extract_pcap_payloads(data)
    frames, warnings = scan_frames(data)
    for w in warnings[:10]:
        print(f"警告：{w}", file=sys.stderr)
    if len(warnings) > 10:
        print(f"警告：共 {len(warnings)} 条校验告警（仅显示前 10）", file=sys.stderr)
    if not frames:
        print(
            "错误：未解析到任何帧——检查采集过滤条件（mesh 数据面 TCP 流方向）",
            file=sys.stderr,
        )
        return 2
    return report(frames, args.require_padding)


if __name__ == "__main__":
    sys.exit(main())
