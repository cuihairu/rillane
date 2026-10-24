# P2-6 Mesh TCP envelope 二进制化（设计稿）

> 2026-10-02 就绪；**M0–M1 已落地**（同提交，TCP 面一次性切换 + 接收侧双格式嗅探）。定位依据：todo P2-6「mesh envelope 二进制化」；
> `udp-mesh-dataplane.md` §2（UDP 面二进制帧格式）与 §末「P2-6 直接采用
> 本格式为统一协议 v2，TCP 面迁移时 UDP 面已是该格式」。UDP 面 `UdpEnvelope`
> 自 P0-4 起即二进制；本条目把 **TCP 面** `MeshEnvelope` 的序列化从 JSON
> 换为二进制头（复用同风格布局），降低每流固定开销。

## 0. 可测口径

1. **帧形**：`write_envelope` 产出的帧体以 magic `'S''U'` + ver=2 开头，
   不再是 JSON 文本（`{` 开头）；二进制解码往返还原全部字段（golden）。
2. **降级接收**：旧 JSON 帧（首字节 `{`）仍可被 `decode_envelope_payload`
   按既有路径解析（P1-4 pad/strip 语义不变）；混布升级窗口内本侧可读旧帧，
   旧侧不可读本侧帧（fail-stop，连接错 = 故障转移，不静默错转发）。
3. **填充共存**：P1-4 `pad_len` 进入二进制头（`pad_len(4)` 字段），
   填充帧 = 二进制头 + K×0x00；strip 校验（pad_len == 帧尾 0x00 数）与
   version 门（填充要求 version ≥ 2）语义与 JSON 时代一致。

## 1. 现状

- TCP 面 `MeshEnvelope{version, flow_id, target_host, target_port, path, pad_len}`
  以 `serde_json` 序列化进 `[len:u32][payload]` 帧（`write_envelope` /
  `read_envelope`）；每跳 `dial_and_tunnel` 剥自身后重编码。
- P1-4 在该 JSON 上叠了尾部 0x00 填充 + `pad_len` 字段（version=2 门）。
- UDP 面已有二进制 `UdpEnvelope`（`UDP_ENVELOPE_VERSION=1`），两套编解码
  并存于同文件 `mesh_transport.rs`。

## 2. 裁决

- **D-1 接收侧嗅探双格式**：帧体首字节 `{`（0x7B）→ 旧 JSON 路径；
  否则须以 `'S''U'` magic 开头，ver 必须为 2 → 二进制路径。发送侧只发二进制。
- **D-2 头布局**（大端，与 UDP §2 同风格）：

```
偏移  字段
0     magic(2) = 'S''U'
2     ver(1)   = 2（二进制 TCP envelope；1 保留=旧 JSON 只收不发）
3     flags(1) : bit0..7 保留必须为 0
4     version(4, BE)  P1-4 填充能力门（1=普通 / 2=填充），原 env.version
8     flow_id_len(1) + flow_id bytes（字符串原文，非空 ≤ 255）
…     host_len(1) + host bytes（domain/v4/v6 字符串化，同 JSON 语义）
…     target_port(2, BE)
…     hop_count(1) + node_id × hop_count（每项 len(1)+bytes）
…     pad_len(4, BE)（P1-4 填充声明；0 = 无填充）
…     [pad]    K × 0x00（K == pad_len）
```

- **D-3 `env.version` 语义保留**：二进制头内显式携带原 version 字段
  （P1-4 门沿用：填充帧 version=2、未填充 version=1）；结构 ver=2 表示
  「二进制编码 v2」，与 env.version 正交不混用。
- **D-4 校验**：magic / ver / flags 保留位 / 各 len 上界 /
  pad_len == 帧尾 0x00 数（E7）/ version 携带填充须 ≥ 2（E7）；截断一律 Err。
- **D-5 `MeshEnvelope` 结构体不动**：仅编解码替换；`pad_envelope_frame`
  内部改走二进制编码（固定点迭代口径不变）；旧测试中「未填充帧逐字节等于
  旧 JSON」的断言升级为「未填充帧逐字节等于二进制 golden」，旧 JSON 字节
  级兼容降级为接收侧 sniff 单测。
- **D-6 零新依赖、零配置面**：无协商，发送侧即日切换；混布窗口旧节点
  收到二进制帧 → 版本检查失败关闭连接（P1-4 同款 R-obfs2 假设：同版本
  部署为 MVP 前提）。

## 3. 错误路径

| # | 条件 | 语义 |
|---|------|------|
| E1 | magic 不符 | Err 丢帧 |
| E2 | ver ≠ 2 且首字节非 `{` | Err 丢帧 |
| E3 | flags 保留位非 0 | Err 丢帧 |
| E4 | len 字段越界 / 截断 | Err 丢帧 |
| E5 | pad_len ≠ 帧尾 0x00 数 | Err（E7 语义同 JSON 期） |
| E6 | version < 2 且携带填充 | Err（E7 语义同 JSON 期） |

## 4. 接线点

| 点 | 动作 |
|---|------|
| `write_envelope` | JSON → `encode_mesh_envelope_binary` |
| `decode_envelope_payload` | 嗅探：`{` → 旧 JSON 解析；否则二进制解析；E5/E6 两道门两格式共用 |
| `pad_envelope_frame` | base 取二进制长度，固定点不变 |
| `read_envelope` | 不变（经 `decode_envelope_payload`） |

## 5. 控制面/指标

无新增。二进制化对调用方透明。

## 6. 测试（§7）

1. 二进制 golden：encode→decode 全字段往返 + 逐字节形状钉（magic/ver/flags/
   version/各 len/pad_len）。
2. 旧 JSON 接收：`serde_json` 旧字节进 `decode_envelope_payload` 字段还原
   （P1-4 pad/strip 语义保留——version=2+pad_len+zeros 的旧帧形也可解析）。
3. pad/strip 全链路：fixed 填充帧总长 == target、尾 zeros == pad_len、
   decode 还原字段、version 升 2（沿用 P1-4 golden，口径切到二进制）。
4. E5/E6 拒帧（构造旧 JSON 与新二进制两形）。
5. TCP 全链路（`dial_and_tunnel` mock 双平面）：wire 帧 = 二进制 golden、
   回显不破。

## 7. 分步

| 步 | 内容 | 验收 |
|---|------|------|
| M0 | 设计稿 + 二进制编解码（纯函数）+ §6-1/2/4 单测 | 编解码往返绿 |
| M1 | `write_envelope`/`decode_envelope_payload`/`pad_envelope_frame` 切换 + §6-3/5 + 文档回填 | 全绿 |

## 8. 偏差与未决

- **§9-1 接收侧嗅探的安全性假设**：JSON 帧恒以 `{` 开头（`serde_json`
  对 struct 确实如此）；二进制帧恒以 `'S'`(0x53) 开头——两者不相交。
  若未来引入以 `{` 开头的新格式须重新登记。
- **O-1**：旧节点在混布窗口内收到二进制帧即连接失败（版本检查硬错，
  非降级忽略）——MVP 同版本部署假设已在 P1-4 登记（R-obfs2），此处
  继承；滚动升级需先全量停写 chain 流量或按拓扑顺序升级。
- **O-2**：`flow_id` 以 len(1)+bytes 字符串原文承载（与 UDP `[u8;16]`
  不同——TCP 面历史上允许非 UUID 形，如测试 "flow1"）；统一归 UUID 形
  的裁剪留 V2。
