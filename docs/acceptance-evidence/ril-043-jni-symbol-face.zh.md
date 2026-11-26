# RIL-043 移动批次 FFI——JNI 符号面（本地可核验段，2026-11-26）

## 本次交付

`crates/rillane-ffi/tests/jni_symbol_face.rs`（3/3 绿）钉住 Android JNI 桥接
契约：Kotlin 宿主 `RillaneFfi` object（platforms/android/.../RillaneFfi.kt 的
`external fun <name>`）与 Rust 侧 `jni_bridge.rs` 导出符号
（`Java_com_rillane_rillane_RillaneFfi_<name>`）方法名集合**恰等**。这是宿主
桥接的链接契约：

- Rust 导出了 Kotlin 未声明的符号 → 线面上不可达的死符号；
- Kotlin 声明了 Rust 未导出的方法 → 库加载期 `UnsatisfiedLinkError`
  （运行期炸，不是编译期）。

本门另钉已知 14 方法面（4 生命周期/状态 + 8 查询 + 2 TUN fd 面）——收窄
桥接面必须是显式动作；两个 `#[should_panic]` 自证门分别注入幻影 Kotlin
声明与幻影 Rust 导出，证明对账器会点名漂移侧。

RIL-083 的 C 头门（contract_query_face.rs）显式把 JNI 面留给 RIL-043 批次门
——本段交付符号面的这扇门。

## 诚实边界

RIL-043 真实验收——fd 与公开 packetFlow 双向桥接、无悬空指针、取消后无回调、
队列有界、真机 ABI 版本面——需移动真机批次（RIL-094 iOS 设备未接入；
Android 完整转发批次待）。主勾选保持关闭；本段只覆盖两侧宿主桥接的静态
可核验符号恰等，依 RIL-150/RIL-090「内容可独立交付」先例办理。

提交前已跑全 workspace 测试、`cargo fmt --all -- --check` 与 clippy
`-D warnings`，全绿。未创建任何正式版本、tag 或 GitHub Release。
