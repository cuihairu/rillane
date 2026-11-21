//! Windows 进程归属真机 IO 面（RIL-034 机批次）：iphlpapi 表探针 +
//! kernel32 身份源，装配进 [`super::win_owner::WinOwnerResolver::with_real_sources`]。
//!
//! FFI 面（与 [`super::win_tun`] 同纪律：iphlpapi 非默认链接库走
//! `LoadLibraryW`/`GetProcAddress` 动态解析，kernel32 直 extern，不引
//! windows-sys/winapi 依赖）：
//! - **表探针** `GetExtendedTcpTable`/`GetExtendedUdpTable`
//!   （`*_OWNER_PID` 表类——OWNER_MODULE 的启动时间列是连接创建时间
//!   不是进程启动时间，module 头注记的缺口不因换表类消失，取更简的
//!   OWNER_PID 即可）。字节序（真机待验，探针 P0 自验）：地址网络序
//!   （`Ipv4Addr::from(u32::from_be(raw))`）、端口取低 16 位网络序
//!   （`u16::from_be((raw & 0xFFFF) as u16)`）——任何解码错误会让探针
//!   按已知端口查不到自己的行，机器上立刻现形。
//! - **身份源** `OpenProcess`(PROCESS_QUERY_LIMITED_INFORMATION) +
//!   `GetProcessTimes`(创建时间 FILETIME→Unix 毫秒) +
//!   `QueryFullProcessImageNameW`(完整路径)。OpenProcess 失败（进程已
//!   退 / 受保护进程 PPL 拒绝）→ `None`——契约口径（win_owner 模块头）：
//!   身份源查无一律 NotFound，不区分「刚退」与「拒绝」，决策层的
//!   PermissionDenied 只来自表探针 Denied。
//! - **错误映射**：表读 `ERROR_ACCESS_DENIED`(5) → `Denied`；缓冲不足
//!   (122) 按返回尺寸重试（上限 5 次，表可在两次调用间增长）；其余
//!   非零码 → 打印诊断后按 `Denied` 保守处理（宁可每查每现探的
//!   PermissionDenied，不入 NotFound 负缓存——错标「socket 已关」会
//!   污染负缓存）。
//! - UDP 表无远端列，按本地侧（地址+端口）匹配；TCP 按本地+远端四元组
//!   匹配（TIME_WAIT 行 OwningPid=0，pid 0 进 identity 源必 OpenProcess
//!   失败 → NotFound，语义正确不需特判）。
//! - 具名缺口：`user_id` 恒 None（Windows token RID 口径归后续批次，
//!   不拿 Linux uid 语义冒充）；`comm_truncated` 恒 false（Windows 路径
//!   无 Linux comm 15 字符截断语义）。

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;
use std::sync::{Arc, OnceLock};

use super::owner::{ConnectionKey, ProcessIdentity};
use super::ports::TransportProtocol;
use super::win_owner::{TableProbe, WinIdentitySource, WinTableProbe};

// kernel32（windows-gnu/msvc 默认链接——无需 import lib）
extern "system" {
    fn LoadLibraryW(lpwstring: *const u16) -> *mut c_void;
    fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;
    fn OpenProcess(dwdesiredaccess: u32, binherithandle: i32, dwprocessid: u32) -> *mut c_void;
    fn GetProcessTimes(
        hprocess: *mut c_void,
        lpcreationtime: *mut FileTime,
        lpexittime: *mut FileTime,
        lpkernelfiletime: *mut FileTime,
        lpusertime: *mut FileTime,
    ) -> i32;
    fn QueryFullProcessImageNameW(
        hprocess: *mut c_void,
        dwflags: u32,
        lpexename: *mut u16,
        lpdwsize: *mut u32,
    ) -> i32;
    fn CloseHandle(hobject: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

/// FILETIME（100ns 自 1601-01-01；两 DWORD，读法见 `unix_ms`）
#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

/// FILETIME → Unix 毫秒（1601→1970 差 11_644_473_600 s）
fn filetime_unix_ms(ft: &FileTime) -> Option<u64> {
    let ticks = (ft.high as u64) << 32 | ft.low as u64;
    (ticks / 10_000).checked_sub(11_644_473_600_000)
}

/// PROCESS_QUERY_LIMITED_INFORMATION（Vista+；够查时间与映像路径，
/// 对 PPL 受保护进程恒被拒——真机权限失败证据面）
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
/// TCP_TABLE_OWNER_PID_CONNECTIONS（仅已建连接行；无 LISTEN 行）
const TCP_TABLE_OWNER_PID_CONNECTIONS: u32 = 4;
/// UDP_TABLE_OWNER_PID
const UDP_TABLE_OWNER_PID: u32 = 1;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_ACCESS_DENIED: u32 = 5;

type GetExtendedTableFn =
    unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, u32, u32) -> u32;

struct IpHelperFns {
    get_extended_tcp_table: GetExtendedTableFn,
    get_extended_udp_table: GetExtendedTableFn,
}

static IPHLPAPI: OnceLock<Result<IpHelperFns, String>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn iphlpapi() -> &'static Result<IpHelperFns, String> {
    IPHLPAPI.get_or_init(|| unsafe {
        let lib = LoadLibraryW(wide("iphlpapi.dll").as_ptr());
        if lib.is_null() {
            return Err(format!("LoadLibraryW(iphlpapi.dll) err={}", GetLastError()));
        }
        let tcp = GetProcAddress(lib, b"GetExtendedTcpTable\0".as_ptr());
        let udp = GetProcAddress(lib, b"GetExtendedUdpTable\0".as_ptr());
        if tcp.is_null() || udp.is_null() {
            return Err(format!(
                "iphlpapi exports missing tcp={} udp={} err={}",
                !tcp.is_null(),
                !udp.is_null(),
                GetLastError()
            ));
        }
        Ok(IpHelperFns {
            get_extended_tcp_table: std::mem::transmute::<*mut c_void, GetExtendedTableFn>(tcp),
            get_extended_udp_table: std::mem::transmute::<*mut c_void, GetExtendedTableFn>(udp),
        })
    })
}

// —— IP Helper 表行（MSDN MIB_*_OWNER_PID；全部按字节切片读，不做
//    指针对齐转换）——

/// MIB_TCPROW_OWNER_PID：state, localAddr, localPort, remoteAddr,
/// remotePort, owningPid（各 u32，行宽 24）
const TCP_ROW_LEN: usize = 24;
/// MIB_UDPROW_OWNER_PID：localAddr, localPort, owningPid（行宽 12）
const UDP_ROW_LEN: usize = 12;
/// MIB_TCP6ROW_OWNER_PID：localAddr[16], localScopeId, remoteAddr[16],
/// remoteScopeId, state, localPort, remotePort, owningPid（行宽 56）
const TCP6_ROW_LEN: usize = 56;
/// MIB_UDP6ROW_OWNER_PID：localAddr[16], localScopeId, localPort,
/// owningPid（行宽 28）
const UDP6_ROW_LEN: usize = 28;

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().expect("u32 slice"))
}

/// DWORD 网络序地址 → Ipv4Addr（低字节是首八位组——MSDN 采样换算口径）
fn ipv4_at(buf: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(u32_at(buf, off)))
}

/// DWORD 网络序端口（低 16 位有效）→ u16
fn port_at(buf: &[u8], off: usize) -> u16 {
    u16::from_be((u32_at(buf, off) & 0xFFFF) as u16)
}

fn v4_sockaddr(buf: &[u8], addr_off: usize, port_off: usize) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        ipv4_at(buf, addr_off),
        port_at(buf, port_off),
    ))
}

fn v6_sockaddr(buf: &[u8], addr_off: usize, port_off: usize) -> SocketAddr {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&buf[addr_off..addr_off + 16]);
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(bytes),
        port_at(buf, port_off),
        0,
        0,
    ))
}

/// 单次表读取：空缓冲探尺寸（122→按返回尺寸扩）重试，上限 5 次。
/// `bOrder=FALSE`——全行扫描自匹配，不依赖排序。
fn read_table(get_fn: GetExtendedTableFn, table_class: u32, af: u32) -> Result<Vec<u8>, u32> {
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..5 {
        let mut size = buf.len() as u32;
        let rc = unsafe {
            get_fn(
                if buf.is_empty() {
                    ptr::null_mut()
                } else {
                    buf.as_mut_ptr() as *mut c_void
                },
                &mut size,
                0,
                af,
                table_class,
                0,
            )
        };
        if rc == ERROR_SUCCESS {
            buf.truncate(size as usize);
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc);
        }
        if buf.len() < size as usize {
            buf.resize(size as usize, 0);
        }
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// 表读取错误 → 探针结果：5=Denied；其余保守按 Denied + 诊断打印
///（不入 NotFound 负缓存，见模块头）
fn table_error(rc: u32) -> TableProbe {
    if rc != ERROR_ACCESS_DENIED {
        eprintln!("win_owner_ffi: table read err={rc} -> denied(conservative)");
    }
    TableProbe::Denied
}

/// TCP 四元组匹配（本地+远端；v6 key 走 v6 表）。同四元组多行并存
/// 窗口（TIME_WAIT 残留 OwningPid=0 + SO_REUSEADDR 新连接）优先非零
/// pid——活归属优先于内核残留；仅剩 pid 0 行时如实返回 Pid(0)
///（identity 源 OpenProcess(0) 必败 → NotFound，语义正确，见模块头）。
fn probe_tcp(key: &ConnectionKey, get_fn: GetExtendedTableFn) -> TableProbe {
    if matches!(key.local, SocketAddr::V6(_)) {
        return probe_tcp6(key, get_fn);
    }
    match read_table(get_fn, TCP_TABLE_OWNER_PID_CONNECTIONS, AF_INET) {
        Ok(buf) => {
            let count = u32_at(&buf, 0) as usize;
            let mut zero_pid: Option<TableProbe> = None;
            for i in 0..count {
                let base = 4 + i * TCP_ROW_LEN;
                if base + TCP_ROW_LEN > buf.len() {
                    break;
                }
                let row = &buf[base..base + TCP_ROW_LEN];
                if v4_sockaddr(row, 4, 8) == key.local && v4_sockaddr(row, 12, 16) == key.remote {
                    let pid = u32_at(row, 20);
                    if pid != 0 {
                        return TableProbe::Pid(pid);
                    }
                    zero_pid = Some(TableProbe::Pid(0));
                }
            }
            zero_pid.unwrap_or(TableProbe::Absent)
        }
        Err(rc) => table_error(rc),
    }
}

fn probe_tcp6(key: &ConnectionKey, get_fn: GetExtendedTableFn) -> TableProbe {
    match read_table(get_fn, TCP_TABLE_OWNER_PID_CONNECTIONS, AF_INET6) {
        Ok(buf) => {
            let count = u32_at(&buf, 0) as usize;
            let mut zero_pid: Option<TableProbe> = None;
            for i in 0..count {
                let base = 4 + i * TCP6_ROW_LEN;
                if base + TCP6_ROW_LEN > buf.len() {
                    break;
                }
                let row = &buf[base..base + TCP6_ROW_LEN];
                // localAddr@0 localScope@16 remoteAddr@20 remoteScope@36
                // state@40 localPort@44 remotePort@48 pid@52
                if v6_sockaddr(row, 0, 44) == key.local && v6_sockaddr(row, 20, 48) == key.remote {
                    let pid = u32_at(row, 52);
                    if pid != 0 {
                        return TableProbe::Pid(pid);
                    }
                    zero_pid = Some(TableProbe::Pid(0));
                }
            }
            zero_pid.unwrap_or(TableProbe::Absent)
        }
        Err(rc) => table_error(rc),
    }
}

/// UDP 本地侧匹配（表无远端列——key.remote 不参与，见模块头）
fn probe_udp(key: &ConnectionKey, get_fn: GetExtendedTableFn) -> TableProbe {
    if matches!(key.local, SocketAddr::V6(_)) {
        return probe_udp6(key, get_fn);
    }
    match read_table(get_fn, UDP_TABLE_OWNER_PID, AF_INET) {
        Ok(buf) => {
            let count = u32_at(&buf, 0) as usize;
            for i in 0..count {
                let base = 4 + i * UDP_ROW_LEN;
                if base + UDP_ROW_LEN > buf.len() {
                    break;
                }
                let row = &buf[base..base + UDP_ROW_LEN];
                if v4_sockaddr(row, 0, 4) == key.local {
                    return TableProbe::Pid(u32_at(row, 8));
                }
            }
            TableProbe::Absent
        }
        Err(rc) => table_error(rc),
    }
}

fn probe_udp6(key: &ConnectionKey, get_fn: GetExtendedTableFn) -> TableProbe {
    match read_table(get_fn, UDP_TABLE_OWNER_PID, AF_INET6) {
        Ok(buf) => {
            let count = u32_at(&buf, 0) as usize;
            for i in 0..count {
                let base = 4 + i * UDP6_ROW_LEN;
                if base + UDP6_ROW_LEN > buf.len() {
                    break;
                }
                let row = &buf[base..base + UDP6_ROW_LEN];
                // localAddr@0 localScope@16 localPort@20 pid@24
                if v6_sockaddr(row, 0, 20) == key.local {
                    return TableProbe::Pid(u32_at(row, 24));
                }
            }
            TableProbe::Absent
        }
        Err(rc) => table_error(rc),
    }
}

/// 真机表探针源：iphlpapi OWNER_PID 表 → [`TableProbe`]
pub fn real_table_probe() -> WinTableProbe {
    Arc::new(move |key: &ConnectionKey| match key.transport {
        TransportProtocol::Tcp => match iphlpapi() {
            Ok(fns) => probe_tcp(key, fns.get_extended_tcp_table),
            Err(e) => {
                eprintln!("win_owner_ffi: {e}");
                TableProbe::Denied
            }
        },
        TransportProtocol::Udp => match iphlpapi() {
            Ok(fns) => probe_udp(key, fns.get_extended_udp_table),
            Err(e) => {
                eprintln!("win_owner_ffi: {e}");
                TableProbe::Denied
            }
        },
    })
}

/// 真机身份源：OpenProcess(QUERY_LIMITED) + GetProcessTimes +
/// QueryFullProcessImageNameW。失败（已退/PPL 拒绝/权限不足）→ None
/// ——契约口径一律 NotFound（见模块头）。诊断打印带 GetLastError 供
/// 真机证据引用。
pub fn real_identity_source() -> WinIdentitySource {
    Arc::new(move |pid: u32| {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            eprintln!("win_owner_ffi: OpenProcess({pid}) failed err={}", unsafe {
                GetLastError()
            });
            return None;
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        let times_ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        let started_at_unix_ms = if times_ok != 0 {
            filetime_unix_ms(&creation)
        } else {
            None
        };
        let mut name_buf = [0u16; 1024];
        let mut name_len = name_buf.len() as u32;
        let name_ok =
            unsafe { QueryFullProcessImageNameW(handle, 0, name_buf.as_mut_ptr(), &mut name_len) };
        unsafe { CloseHandle(handle) };
        if times_ok == 0 && name_ok == 0 {
            eprintln!("win_owner_ffi: OpenProcess({pid}) ok but times/name both failed");
            return None;
        }
        let executable_path = if name_ok != 0 {
            let s = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let trimmed = s.trim_end_matches('\0');
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        } else {
            None
        };
        let process_name = executable_path
            .as_ref()
            .map(|p| p.rsplit(['\\', '/']).next().unwrap_or(p).to_string());
        Some(ProcessIdentity {
            pid,
            started_at_unix_ms,
            executable_path,
            process_name,
            comm_truncated: false,
            user_id: None,
        })
    })
}
