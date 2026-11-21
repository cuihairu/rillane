//! Windows 数据面（RIL-033 机批次）：Wintun 用户态会话 = Windows 的
//! TUN 等价物，实现 RIL-004 [`CapturePort`]。
//!
//! **选型事实（wireguard-nt vs Wintun，2026-11-21 机批次钉死）**：
//! wireguard-nt 是**纯内核实现**——官方 API 只有适配器管理面
//! （WireGuardCreateAdapter/SetConfiguration/SetAdapterState），文档原话
//! "all tunnel packet I/O is performed by the NT kernel driver itself"，
//! **不存在用户态收发包函数**；rillane 需要在用户态读包入代理栈，故
//! 数据面只能走 Wintun（0.14 用户态封环 API：CreateAdapter/
//! StartSession/ReceivePacket/SendPacket）。wireguard-nt 面（内核加密
//! 隧道）留作上游对接的可选层，不在本模块。机上事实：wintun.sys 0.14
//! 已在驱动库（RIL-032 pnputil 实测），wireguard-tools 安装目录无任何
//! 用户态 wireguard DLL——FFI 目标为随探针部署的 wintun.dll（官方构建
//! 0.14.1）。
//!
//! 加载方式：`LoadLibraryW("wintun.dll")` 动态解析全部导出（不引
//! windows-sys/winapi 依赖；kernel32 三函数直 extern）。探针/宿主把
//! wintun.dll 放在 exe 旁，LoadLibrary 默认搜索路径命中。
//!
//! 契约对齐（RIL-004）：[`WinTunCapturePort::recv`] 就绪语义——环空时
//! `WouldBlock`（与 Linux [`super::takeover::LinuxTakeoverPort`] 的
//! mpsc Empty 同口径，不自旋）；解析失败计数跳过不中断；包经
//! [`super::ipcodec::parse_packet_meta`] 归一中立元数据。

use std::ffi::c_void;
use std::io;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::{Arc, Mutex};

use super::ipcodec::parse_packet_meta;
use super::ports::{CapturePort, CapturedInput, PacketInput};

/// Wintun 环容量下限（wintun.h WINTUN_MIN_RING_CAPACITY，128 KiB）
pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x20000;
/// Wintun 环容量上限（wintun.h WINTUN_MAX_RING_CAPACITY，64 MiB）
pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x4000000;
/// 单包上限（wintun.h WINTUN_MAX_IP_PACKET_SIZE）
pub const WINTUN_MAX_IP_PACKET_SIZE: u32 = 0xFFFF;

type AdapterHandle = *mut c_void;
type SessionHandle = *mut c_void;

/// 最近一次系统错误码（Win32 错误面）。FFI 调用后取——wintun 自身不
/// 返回错误码，失败只给 NULL，真相在 LastError（RIL-033 真机诊断面）。
pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

// kernel32 加载面（windows-gnu/msvc 默认链接 kernel32——无需 import lib）
extern "system" {
    fn LoadLibraryW(lpwstring: *const u16) -> *mut c_void;
    fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;
    fn FreeLibrary(hlibmodule: *mut c_void) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn GetLastError() -> u32;
}

// wintun.h 全签名（0.14.1；stdcall/x64 = system ABI）
type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> AdapterHandle;
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut u64);
type DriverVersionFn = unsafe extern "system" fn() -> u32;
type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSessionFn = unsafe extern "system" fn(SessionHandle);
type ReadWaitEventFn = unsafe extern "system" fn(SessionHandle) -> *mut c_void;
type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *const u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(SessionHandle, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

#[derive(Clone, Copy)]
struct Exports {
    create_adapter: CreateAdapterFn,
    open_adapter: OpenAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    driver_version: DriverVersionFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    read_wait_event: ReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
}

/// wintun.dll 加载句柄（Drop = FreeLibrary）
pub struct WintunApi {
    module: *mut c_void,
    exports: Exports,
}

// 句柄仅作不透明指针传递；FFI 函数本身线程安全面见 wintun 文档
unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

impl WintunApi {
    /// 动态加载 wintun.dll 并解析全部所需导出；任一导出缺失即报错
    /// （不猜形状——0.12 起环 API 稳定，缺导出 = 版本不兼容）
    pub fn load(dll_path: &str) -> io::Result<Self> {
        let wide: Vec<u16> = std::ffi::OsStr::new(dll_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            let get = |name: &'static str| -> io::Result<*mut c_void> {
                let sym = std::ffi::CString::new(name).unwrap();
                let p = GetProcAddress(module, sym.as_ptr().cast());
                if p.is_null() {
                    Err(io::Error::other(format!("wintun.dll 缺导出 {name}")))
                } else {
                    Ok(p)
                }
            };
            macro_rules! need {
                ($name:literal, $ty:ty) => {
                    std::mem::transmute::<*mut c_void, $ty>(get($name)?)
                };
            }
            let exports = Exports {
                create_adapter: need!("WintunCreateAdapter", CreateAdapterFn),
                open_adapter: need!("WintunOpenAdapter", OpenAdapterFn),
                close_adapter: need!("WintunCloseAdapter", CloseAdapterFn),
                get_adapter_luid: need!("WintunGetAdapterLUID", GetAdapterLuidFn),
                driver_version: need!("WintunGetRunningDriverVersion", DriverVersionFn),
                start_session: need!("WintunStartSession", StartSessionFn),
                end_session: need!("WintunEndSession", EndSessionFn),
                read_wait_event: need!("WintunGetReadWaitEvent", ReadWaitEventFn),
                receive_packet: need!("WintunReceivePacket", ReceivePacketFn),
                release_receive_packet: need!("WintunReleaseReceivePacket", ReleaseReceivePacketFn),
                allocate_send_packet: need!("WintunAllocateSendPacket", AllocateSendPacketFn),
                send_packet: need!("WintunSendPacket", SendPacketFn),
            };
            Ok(Self { module, exports })
        }
    }

    /// 运行中驱动版本（0x00050000 风格编码；0 = 驱动未装）
    pub fn running_driver_version(&self) -> u32 {
        unsafe { (self.exports.driver_version)() }
    }

    fn wide(name: &str) -> Vec<u16> {
        std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl Drop for WintunApi {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

/// Wintun 适配器（Create 或 Open；Drop = CloseAdapter）
pub struct WintunDevice {
    api: Arc<WintunApi>,
    adapter: AdapterHandle,
}

// 适配器句柄为不透明对象指针；wintun API 声明适配器调用线程安全
unsafe impl Send for WintunDevice {}
unsafe impl Sync for WintunDevice {}

impl WintunDevice {
    /// 创建适配器（需管理员；GUID None = 随机生成）。TunnelType 仅作
    /// 适配器描述，用产品名便于真机辨识。
    pub fn create(api: &Arc<WintunApi>, name: &str, tunnel_type: &str) -> io::Result<Self> {
        let n = WintunApi::wide(name);
        let t = WintunApi::wide(tunnel_type);
        let adapter = unsafe { (api.exports.create_adapter)(n.as_ptr(), t.as_ptr(), ptr::null()) };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            api: api.clone(),
            adapter,
        })
    }

    /// 打开既有适配器（同进程重启/接管恢复路径）
    pub fn open(api: &Arc<WintunApi>, name: &str) -> io::Result<Self> {
        let n = WintunApi::wide(name);
        let adapter = unsafe { (api.exports.open_adapter)(n.as_ptr()) };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            api: api.clone(),
            adapter,
        })
    }

    /// NET_LUID（u64 位型；转 ifIndex 用 `(luid & 0xFFFFFF) as u32`——
    /// Windows 保留低 24 位为 ifIndex）
    pub fn luid(&self) -> u64 {
        let mut luid = 0u64;
        unsafe { (self.api.exports.get_adapter_luid)(self.adapter, &mut luid) };
        luid
    }

    /// 会话 If 索引（路由 `-if` 参数用；低 24 位）
    pub fn if_index(&self) -> u32 {
        (self.luid() & 0xFF_FFFF) as u32
    }

    /// 开会话（容量须在 [128 KiB, 64 MiB]；失败即 LastError）
    pub fn start_session(&self, capacity: u32) -> io::Result<WintunSession> {
        if !(WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY).contains(&capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("环容量 {capacity} 出界 [{WINTUN_MIN_RING_CAPACITY}, {WINTUN_MAX_RING_CAPACITY}]"),
            ));
        }
        let session = unsafe { (self.api.exports.start_session)(self.adapter, capacity) };
        if session.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(WintunSession {
            api: self.api.clone(),
            session,
        })
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        unsafe { (self.api.exports.close_adapter)(self.adapter) };
    }
}

/// Wintun 会话（用户态封环；Drop = EndSession）。收发走两把锁分面：
/// 接收单线程纪律（wintun 文档），发送可并发（Allocate 线程安全）。
pub struct WintunSession {
    api: Arc<WintunApi>,
    session: SessionHandle,
}

unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl WintunSession {
    /// 读就绪事件句柄（WAIT_OBJECT_0 = 环有包；0 超时 = 轮询语义）。
    /// 句柄生命周期跟随会话——不得在 EndSession 后使用。
    pub fn wait_handle(&self) -> *mut c_void {
        unsafe { (self.api.exports.read_wait_event)(self.session) }
    }

    /// 就绪轮询（不阻塞）：环有包 = true
    pub fn has_packet_ready(&self) -> bool {
        unsafe { WaitForSingleObject(self.wait_handle(), 0) == 0 } // WAIT_OBJECT_0
    }

    /// 收一个包（拷贝出环并释放环槽位）。环空 = `Ok(None)`（就绪语义，
    /// 由调用方决定轮询/挂事件）；其它失败 = LastError。
    pub fn receive(&self) -> io::Result<Option<Vec<u8>>> {
        let mut size = 0u32;
        let pkt = unsafe { (self.api.exports.receive_packet)(self.session, &mut size) };
        if pkt.is_null() {
            let err = io::Error::last_os_error();
            // ERROR_NO_MORE_ITEMS (259) = 环空，非错误
            return if err.raw_os_error() == Some(259) {
                Ok(None)
            } else {
                Err(err)
            };
        }
        let bytes = unsafe { std::slice::from_raw_parts(pkt, size as usize) }.to_vec();
        unsafe { (self.api.exports.release_receive_packet)(self.session, pkt) };
        Ok(Some(bytes))
    }

    /// 发一个包进栈（下行；IP 整包，≤ 0xFFFF）。环满（Allocate 失败
    /// ERROR_BUFFER_OVERFLOW）= 显式错误不静默丢。
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() as u64 > WINTUN_MAX_IP_PACKET_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "包长 {} 出界 (1, {WINTUN_MAX_IP_PACKET_SIZE}]",
                    packet.len()
                ),
            ));
        }
        let slot =
            unsafe { (self.api.exports.allocate_send_packet)(self.session, packet.len() as u32) };
        if slot.is_null() {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len());
            (self.api.exports.send_packet)(self.session, slot);
        }
        Ok(())
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        unsafe { (self.api.exports.end_session)(self.session) };
    }
}

/// 捕获端口用量（与 Linux [`super::takeover::TakeoverPortStats`] 同构）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WinTunPortStats {
    /// 已捕获进契约面的包数
    pub captured: u64,
    /// L3 元数据解析失败跳过数（坏包不当零不当丢）
    pub parse_errors: u64,
}

/// RIL-004 [`CapturePort`] 的 Windows 实现：Wintun 环 → 中立捕获输入。
/// 接收面单线程纪律由内部互斥承载（recv(&mut self) 契约本身就排除
/// 并发 recv——锁只保护 stats 与 FFI 调用的串行化）。
pub struct WinTunCapturePort {
    session: WintunSession,
    stats: Mutex<WinTunPortStats>,
}

impl WinTunCapturePort {
    /// 由已开会话构造
    pub fn new(session: WintunSession) -> Self {
        Self {
            session,
            stats: Mutex::new(WinTunPortStats::default()),
        }
    }

    /// 端口用量快照
    pub fn stats(&self) -> WinTunPortStats {
        *self.stats.lock().expect("锁")
    }

    /// 下行发包直通（代理栈回注用；与 recv 分面无锁竞争）
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.session.send(packet)
    }

    /// 会话就绪轮询（async 适配器挂事件用）
    pub fn has_packet_ready(&self) -> bool {
        self.session.has_packet_ready()
    }
}

impl CapturePort for WinTunCapturePort {
    fn recv(&mut self) -> io::Result<Option<CapturedInput>> {
        loop {
            match self.session.receive()? {
                None => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Some(bytes) => {
                    match parse_packet_meta(&bytes) {
                        Ok(meta) => {
                            self.stats.lock().expect("锁").captured += 1;
                            return Ok(Some(CapturedInput::Packet(PacketInput {
                                packet: bytes,
                                meta,
                            })));
                        }
                        Err(_) => {
                            self.stats.lock().expect("锁").parse_errors += 1;
                            // 坏包跳过继续（不当零不当丢，计数可见）
                        }
                    }
                }
            }
        }
    }
}

/// 探针/装配面的旁路地址辅助：bind IP 为 v6 时须全局单播（链路本地
/// 不可作出站目标——win_takeover [`super::win_takeover::V6AddrKind`]
/// 分类已挡）；此处只做类型断言防误用。
pub fn assert_bindable(ip: IpAddr) -> io::Result<()> {
    match ip {
        IpAddr::V4(_) => Ok(()),
        IpAddr::V6(v6) if !v6.is_loopback() && v6.segments()[0] & 0xffc0 != 0xfe80 => Ok(()),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v6 bind 地址须为全局单播（链路本地/回环不可作出站目标）",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 环容量校验（OS-free；FFI 加载面归真机探针——Linux 席上不引 DLL）
    #[test]
    fn ring_capacity_bounds_are_enforced_without_dll() {
        // load 失败路径也不 panic（Linux 席无 DLL——但本模块 cfg windows
        // 整体不参与 Linux 测试，此测试仅在 windows 席编译运行）
        assert!((WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY)
            .contains(&WINTUN_MIN_RING_CAPACITY));
    }

    /// bind 地址类型断言（OS-free 纯判定）
    #[test]
    fn bindable_addresses_are_typed() {
        assert!(assert_bindable("192.168.5.117".parse().unwrap()).is_ok());
        assert!(assert_bindable("240e:3a1::1".parse().unwrap()).is_ok());
        assert!(assert_bindable("fe80::1".parse().unwrap()).is_err());
        assert!(assert_bindable("::1".parse().unwrap()).is_err());
    }
}
