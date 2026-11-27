# RIL-044 移动宿主秘密引用注入面（本地可核验段，2026-11-27）

## 交付内容

`crates/rillane-ffi/tests/secret_injection_contract.rs`（4/4 绿）把 RIL-044
验收条款「配置/秘密引用注入」钉在其 FFI 半边。`rillane_ffi_start_with_secrets`
（新增 C 导出，同提交更新头文件 + JNI 桥 + Kotlin `startWithSecrets` 声明）
在装配 runtime 前把配置 YAML 里的 `${secret:<name>` 引用经 JSON 秘密表解析：

- **注入值真实生效（真实 RFC1929 往返）**：password 为 `${secret:ingress_pw}`
  的 socks5 入站经注入口启动；正确秘密值通过 RFC1929 用户名/密码认证并完成
  直连出口的 CONNECT echo 逐字节往返，错密码与错用户名均被拒（状态 0x01）
  ——注入值确实参与了比对，不是匿名放行。
- **fail-closed，稳定码**：缺引用（`secret.ref.missing`，点名引用键）、坏引用
  （空名/缺右括号，`secret.ref.malformed`）、表非法（非对象/值非字符串/坏
  JSON/空指针，`secret.map.invalid`）、模板漂移双向（缺键点名引用；陈旧未用
  键点名 `secret.map.unused`）全部返回 NULL 并带具名 `last_error`。表补齐后
  同配置即成功启动（不留半挂载状态）。
- **直通口误用拒绝**：配置仍含 `${secret:` 标记时 `rillane_ffi_start` 拒绝
  启动——绝不把引用字面量静默当密码用——并指向正确入口。
- **非递归有行为证明**：替换值本身长得像引用（`"${secret:phantom_ref}"`）时
  按字面量插入——实例照常启动且用该字面量过认证，尽管 `phantom_ref` 不在
  表里；若二次扫描，启动期就会以缺引用拒绝。
- **秘密不进诊断面**：真实流量后，全部查询面（stats/routing/nodes/
  dns_stats/dns_resolvers/flows）原始输出既不含秘密值也不含 `${secret:`
  标记。
- **桥接面同步**：Kotlin 与 Rust 两侧同步加 `startWithSecrets`（后续 RIL-044
  段落后 JNI 恰等门现钉 18 方法），C 头 ↔ Rust 导出恰等门随新声明通过。

## 如实边界

本门只钉 FFI 解析半边。Kotlin 宿主半边——秘密值来源（Keystore/
EncryptedSharedPreferences）、值不进日志的运行期纪律、`startWithSecrets`
真机运行——归 RIL-043 真机批次，保持开放。网络变化通知与有界诊断 IPC 的
核心半边已分别作为本地账本交付——[网络变化](./ril-044-network-change.zh)、
[有界诊断 IPC](./ril-044-diagnostic-ipc.zh)。主勾选保持关闭。
