/*
 * rillane_ffi.h —— RILLANE 移动端 C ABI（P3-4）
 *
 * 供 iOS（NEPacketTunnelProvider 桥接头）/NDK C 层/其他 FFI 消费方引用；
 * Android Kotlin 侧不走本头文件（JNI 符号直连，见 src/jni_bridge.rs）。
 *
 * 内存约定（与 crates/rillane-ffi/src/lib.rs 模块注释一致）：
 * - 本头文件返回的 char* 一律以 rillane_ffi_free_string 归还；
 * - last_error 读后即清，指针在同线程下一次错误覆盖前有效；
 * - rillane_ffi_start 返回的句柄只能配对一次 rillane_ffi_stop。
 */
#ifndef RILLANE_FFI_H
#define RILLANE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄（Rust 侧 FfiHandle） */
typedef struct rillane_ffi_handle rillane_ffi_handle_t;

/* 版本串（进程级静态，无需释放） */
const char *rillane_ffi_version(void);

/* 读取并清空同线程最近一次错误；无错误返回 NULL */
char *rillane_ffi_last_error(void);

/*
 * 以配置 YAML 启动完整 rillane runtime。
 * config_yaml 指向 >= config_len 字节 UTF-8（可带尾随 NUL，会被剔除）。
 * 成功返回句柄；失败返回 NULL（错误见 last_error）。
 */
rillane_ffi_handle_t *rillane_ffi_start(const char *config_yaml, size_t config_len);

/*
 * 以配置 YAML + 秘密引用表启动（RIL-044 配置/秘密引用注入面）。
 * config_yaml 内 `${secret:<name>}` 由 secrets_json（JSON 对象，值全为
 * 字符串）解析替换：单遍非递归（替换值不重扫）、fail-closed——缺引用
 * [secret.ref.missing]、坏引用 [secret.ref.malformed]、表非法
 * [secret.map.invalid]、表含未使用键 [secret.map.unused] 均返回 NULL。
 * 两对指针同 rillane_ffi_start 口径（>= len 字节 UTF-8，可带尾随 NUL）。
 */
rillane_ffi_handle_t *rillane_ffi_start_with_secrets(const char *config_yaml, size_t config_len,
                                                     const char *secrets_json, size_t secrets_len);

/*
 * 通知核心宿主底层网络已变化（RIL-044「网络变化」面）：冲刷 DNS 缓存
 * （换网后旧网缓存应答不再复用）；DNS 缺席/关闭 = 诚实 no-op 仍 0。
 * 可重复调用（幂等）。在途转发流不主动斩断（会话排空归 RIL-022/023
 * 消费侧边界）。0 成功 / -1 句柄无效（错误见 last_error）。
 */
int32_t rillane_ffi_network_changed(const rillane_ffi_handle_t *handle);

/* 停止并释放句柄（TUN 线程先行收尾；句柄此后悬空）。0 成功 / -1 失败 */
int32_t rillane_ffi_stop(rillane_ffi_handle_t *handle);

/* 运行状态：1 运行 / 0 停止 / -1 句柄无效 */
int32_t rillane_ffi_is_running(const rillane_ffi_handle_t *handle);

/* 运行统计 JSON（rillaned 控制面 /stats 同形字段），调用方 free_string */
char *rillane_ffi_stats_json(const rillane_ffi_handle_t *handle);

/*
 * 查询面（RIL-150）——与 rillaned 控制面同字段口径（schema_version=1）；
 * 全部 handle 无效返回 NULL（错误见 last_error），成功返回 JSON 字符串
 * 以 rillane_ffi_free_string 归还。
 */

/* 路由概要：mode/default_node/global_node/direct_node/groups/rules_count */
char *rillane_ffi_routing_json(const rillane_ffi_handle_t *handle);

/* 节点：组实时质量 + 出口节点（name/type，不含凭证）+ 订阅源 */
char *rillane_ffi_nodes_json(const rillane_ffi_handle_t *handle);

/* DNS 统计（/dns/stats 同形；network.dns 缺席 = enabled:false 零值） */
char *rillane_ffi_dns_stats_json(const rillane_ffi_handle_t *handle);

/* DNS 解析器形状（/dns/resolvers 同形；块缺席 = enabled:false 空形态） */
char *rillane_ffi_dns_resolvers_json(const rillane_ffi_handle_t *handle);

/*
 * 活动/近期连接分页（/trace/flows 同形信封）。limit=0 显式拒绝——
 * 返回非 NULL 信封 `{"schema_version":1,"error":"query.page.invalid"}`。
 */
char *rillane_ffi_flows_json(const rillane_ffi_handle_t *handle, size_t offset, size_t limit);

/* 单流详情（/trace/flow 同形；未知/无效 ID = found:false + 稳定码 + 计数） */
char *rillane_ffi_flow_json(const rillane_ffi_handle_t *handle, const char *flow_id);

/*
 * 挂载 TUN fd 并起最小数据通路（ICMP echo 轮转）。
 * fd 所有权转移至本层（调用方 detach 后不得再关闭）；
 * 重复挂载先停旧再起新。0 成功 / -1 失败。
 */
int32_t rillane_ffi_tun_start(rillane_ffi_handle_t *handle, int32_t fd);

/* 停 TUN 线程（fd 随线程收尾关闭）；未挂载亦返回 0（幂等） */
int32_t rillane_ffi_tun_stop(rillane_ffi_handle_t *handle);

/* 释放本头文件返回的字符串；NULL 容忍 */
void rillane_ffi_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* RILLANE_FFI_H */
