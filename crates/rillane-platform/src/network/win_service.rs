//! Windows 服务管理（SCM）FFI（RIL-035 机批次）——advapi32 动态解析
//! （`LoadLibraryW`/`GetProcAddress`，同 [`super::win_tun`]/
//! [`super::win_owner_ffi`] 纪律：任一导出缺失即整体报错，不引
//! windows-sys/winapi 依赖）。
//!
//! **服务端**：`StartServiceCtrlDispatcherW` 阻塞主循环 +
//! `RegisterServiceCtrlHandlerExW`（SERVICE_CONTROL_STOP/SHUTDOWN 置
//! 停止旗）+ `SetServiceStatus`（START_PENDING→RUNNING→STOPPED）。
//! 服务主体经 `run_service` 注入（服务线程内跑一次，随后空转等停）；
//! `StartServiceW` 传参进 `ServiceRun.args`（SCM 崩溃重启不带参——
//! 服务据此区分「apply-route」与「纯恢复」两态）。
//! **客户端**（管理员会话装配面）：`OpenSCManagerW`/`CreateServiceW`
//!（WIN32_OWN_PROCESS + DEMAND_START）/`StartServiceW`/
//! `QueryServiceStatusEx`（SC_STATUS_PROCESS_INFO 含 dwProcessId——
//! 崩溃测试按 pid 定位，勿按映像名误杀自己）/`ControlService`(STOP)/
//! `DeleteService`/`ChangeServiceConfig2W`(FAILURE_ACTIONS——SC_ACTION
//! _RESTART，真机「服务崩溃→SCM 自动重启→恢复」闭环面)。
//!
//! 契约：本模块只做 SCM 生命周期面，不掺业务；恢复语义
//! （`recover_windows`/`win_journaling_executor`/
//! `handle_network_event_windows`）在 [`super::win_recovery`]，
//! 装配在 `examples/win_service_probe.rs`。

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// —— 常量（winnt.h / winsvc.h）——
pub const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
pub const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
pub const SERVICE_DEMAND_START: u32 = 0x3;
pub const SERVICE_ERROR_NORMAL: u32 = 0x1;
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_RUNNING: u32 = 4;
pub const SERVICE_STOP_PENDING: u32 = 5;
pub const SERVICE_ACCEPT_STOP: u32 = 0x1;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x4;
pub const SERVICE_CONTROL_STOP: u32 = 0x1;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x5;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x4;
/// SC_STATUS_PROCESS_INFO（QueryServiceStatusEx 信息级）
pub const SC_STATUS_PROCESS_INFO: u32 = 0;
pub const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
pub const SC_ACTION_RESTART: u32 = 1;
pub const NO_ERROR: u32 = 0;

// kernel32（动态解析底盘公共件）
extern "system" {
    fn LoadLibraryW(lpwstring: *const u16) -> *mut c_void;
    fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
}

/// SERVICE_STATUS（winsvc.h，8×u32）
#[repr(C)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

/// SERVICE_STATUS_PROCESS（9×u32；dwProcessId 供崩溃测试按 pid 定位）
#[repr(C)]
pub struct ServiceStatusProcess {
    pub base: ServiceStatus,
    pub process_id: u32,
    pub service_flags: u32,
}

/// SC_ACTION（winsvc.h）
#[repr(C)]
pub struct ScAction {
    pub action: u32,
    pub delay: u32,
}

/// SERVICE_FAILURE_ACTIONSW（winsvc.h；lpsaActions 指向 ScAction 数组）
#[repr(C)]
pub struct ServiceFailureActionsW {
    pub reset_period: u32,
    pub reboot_msg: *mut u16,
    pub command: *mut u16,
    pub actions: u32,
    pub action_array: *mut ScAction,
}

/// SERVICE_TABLE_ENTRYW（winsvc.h；末项 name=NULL 终结）
#[repr(C)]
pub struct ServiceTableEntryW {
    pub name: *const u16,
    pub service_main: Option<ServiceMainFn>,
}

pub type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);
pub type HandlerExFn = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;
type ServiceStatusHandle = *mut c_void;

// advapi32 导出函数指针形状（win_owner_ffi 同式：具名别名供结构体字段
// 与 transmute turbofish共用——clippy missing_transmute_annotations）
type OpenScManagerFn = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
type OpenServiceFn = unsafe extern "system" fn(*mut c_void, *const u16, u32) -> *mut c_void;
type CreateServiceFn = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const u16,
    u32,
    u32,
    u32,
    u32,
    *const u16,
    *const u16,
    *mut u32,
    *const u16,
    *const u16,
    *const u16,
) -> *mut c_void;
type StartServiceFn = unsafe extern "system" fn(*mut c_void, u32, *const *const u16) -> i32;
type ControlServiceFn = unsafe extern "system" fn(*mut c_void, u32, *mut ServiceStatus) -> i32;
type DeleteServiceFn = unsafe extern "system" fn(*mut c_void) -> i32;
type QueryStatusExFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
type CloseServiceHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
type ChangeServiceConfig2Fn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type StartServiceCtrlDispatcherFn = unsafe extern "system" fn(*mut ServiceTableEntryW) -> i32;
type RegisterServiceCtrlHandlerFn =
    unsafe extern "system" fn(*const u16, HandlerExFn, *mut c_void) -> ServiceStatusHandle;
type SetServiceStatusFn = unsafe extern "system" fn(ServiceStatusHandle, *mut ServiceStatus) -> i32;

/// advapi32 导出集（LoadLibraryW 动态解析；任一缺失=Err）
#[derive(Clone, Copy)]
struct AdvapiFns {
    open_sc_manager: OpenScManagerFn,
    open_service: OpenServiceFn,
    create_service: CreateServiceFn,
    start_service: StartServiceFn,
    control_service: ControlServiceFn,
    delete_service: DeleteServiceFn,
    query_status_ex: QueryStatusExFn,
    close_service_handle: CloseServiceHandleFn,
    change_service_config2: ChangeServiceConfig2Fn,
    start_service_ctrl_dispatcher: StartServiceCtrlDispatcherFn,
    register_service_ctrl_handler: RegisterServiceCtrlHandlerFn,
    set_service_status: SetServiceStatusFn,
}

static ADVAPI32: OnceLock<Result<AdvapiFns, String>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn advapi32() -> &'static Result<AdvapiFns, String> {
    ADVAPI32.get_or_init(|| unsafe {
        let lib = LoadLibraryW(wide("advapi32.dll").as_ptr());
        if lib.is_null() {
            return Err(format!("LoadLibraryW(advapi32.dll) err={}", GetLastError()));
        }
        let lookup = |name: &[u8]| -> Result<*mut c_void, String> {
            let f = GetProcAddress(lib, name.as_ptr());
            if f.is_null() {
                Err(format!(
                    "advapi32 export missing: {}",
                    String::from_utf8_lossy(name)
                ))
            } else {
                Ok(f)
            }
        };
        macro_rules! cast {
            ($name:literal, $ty:ty) => {
                std::mem::transmute::<*mut c_void, $ty>(lookup($name)?)
            };
        }
        Ok(AdvapiFns {
            open_sc_manager: cast!(b"OpenSCManagerW\0", OpenScManagerFn),
            open_service: cast!(b"OpenServiceW\0", OpenServiceFn),
            create_service: cast!(b"CreateServiceW\0", CreateServiceFn),
            start_service: cast!(b"StartServiceW\0", StartServiceFn),
            control_service: cast!(b"ControlService\0", ControlServiceFn),
            delete_service: cast!(b"DeleteService\0", DeleteServiceFn),
            query_status_ex: cast!(b"QueryServiceStatusEx\0", QueryStatusExFn),
            close_service_handle: cast!(b"CloseServiceHandle\0", CloseServiceHandleFn),
            change_service_config2: cast!(b"ChangeServiceConfig2W\0", ChangeServiceConfig2Fn),
            start_service_ctrl_dispatcher: cast!(
                b"StartServiceCtrlDispatcherW\0",
                StartServiceCtrlDispatcherFn
            ),
            register_service_ctrl_handler: cast!(
                b"RegisterServiceCtrlHandlerExW\0",
                RegisterServiceCtrlHandlerFn
            ),
            set_service_status: cast!(b"SetServiceStatus\0", SetServiceStatusFn),
        })
    })
}

// —— 客户端 ——

/// SCM 连接（OpenSCManagerW；Drop 关闭）
pub struct ScmClient {
    handle: *mut c_void,
}

impl ScmClient {
    pub fn open() -> Result<Self, String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let h = unsafe { (fns.open_sc_manager)(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
        if h.is_null() {
            Err(format!("OpenSCManagerW err={}", unsafe { GetLastError() }))
        } else {
            Ok(Self { handle: h })
        }
    }

    /// 创建服务（WIN32_OWN_PROCESS + DEMAND_START，LocalSystem）。
    /// `bin_path` 即 ImagePath 原文（含空格路径由调用方自带引号）；
    /// 已存在=Err（1073），调用方先查再建。
    pub fn create_service(
        &self,
        name: &str,
        display: &str,
        bin_path: &str,
    ) -> Result<ServiceHandle, String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let n = wide(name);
        let d = wide(display);
        let b = wide(bin_path);
        let h = unsafe {
            (fns.create_service)(
                self.handle,
                n.as_ptr(),
                d.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                b.as_ptr(),
                ptr::null(),     // lpLoadOrderGroup
                ptr::null_mut(), // lpdwTagId
                ptr::null(),     // lpDependencies
                ptr::null(),     // lpServiceStartName（=LocalSystem）
                ptr::null(),     // lpPassword
            )
        };
        if h.is_null() {
            Err(format!("CreateServiceW({name}) err={}", unsafe {
                GetLastError()
            }))
        } else {
            Ok(ServiceHandle {
                handle: h,
                name: name.to_string(),
            })
        }
    }

    /// 打开已有服务（不存在=Err 1060）
    pub fn open_service(&self, name: &str) -> Result<ServiceHandle, String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let n = wide(name);
        let h = unsafe { (fns.open_service)(self.handle, n.as_ptr(), SERVICE_ALL_ACCESS) };
        if h.is_null() {
            Err(format!("OpenServiceW({name}) err={}", unsafe {
                GetLastError()
            }))
        } else {
            Ok(ServiceHandle {
                handle: h,
                name: name.to_string(),
            })
        }
    }

    /// 服务在册与否（OpenService 口径）
    pub fn service_exists(&self, name: &str) -> bool {
        self.open_service(name).is_ok()
    }
}

impl Drop for ScmClient {
    fn drop(&mut self) {
        if let Ok(fns) = advapi32() {
            if !self.handle.is_null() {
                unsafe { (fns.close_service_handle)(self.handle) };
            }
        }
    }
}

/// 服务句柄（生命周期操作；Drop 关闭）
pub struct ServiceHandle {
    handle: *mut c_void,
    name: String,
}

impl ServiceHandle {
    /// 启动并传参（`args` → ServiceMain argv[1..]；SCM 失败重启不带参）
    pub fn start(&self, args: &[&str]) -> Result<(), String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let wide_args: Vec<Vec<u16>> = args.iter().map(|s| wide(s)).collect();
        let ptrs: Vec<*const u16> = wide_args.iter().map(|v| v.as_ptr()).collect();
        let ok = unsafe {
            (fns.start_service)(
                self.handle,
                ptrs.len() as u32,
                if ptrs.is_empty() {
                    ptr::null()
                } else {
                    ptrs.as_ptr()
                },
            )
        };
        if ok == 0 {
            Err(format!("StartServiceW({}) err={}", self.name, unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }

    pub fn query_state(&self) -> Result<u32, String> {
        Ok(self.query_status_process()?.base.current_state)
    }

    /// QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)：状态 + 进程 pid
    pub fn query_status_process(&self) -> Result<ServiceStatusProcess, String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let mut buf: ServiceStatusProcess = unsafe { std::mem::zeroed() };
        let mut needed = 0u32;
        let ok = unsafe {
            (fns.query_status_ex)(
                self.handle,
                SC_STATUS_PROCESS_INFO,
                &mut buf as *mut _ as *mut c_void,
                std::mem::size_of::<ServiceStatusProcess>() as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            Err(format!(
                "QueryServiceStatusEx({}) err={}",
                self.name,
                unsafe { GetLastError() }
            ))
        } else {
            Ok(buf)
        }
    }

    /// 停止（SERVICE_CONTROL_STOP；err 1062=已停止）
    pub fn stop(&self) -> Result<(), String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let mut status: ServiceStatus = unsafe { std::mem::zeroed() };
        let ok = unsafe { (fns.control_service)(self.handle, SERVICE_CONTROL_STOP, &mut status) };
        if ok == 0 {
            Err(format!(
                "ControlService(STOP, {}) err={}",
                self.name,
                unsafe { GetLastError() }
            ))
        } else {
            Ok(())
        }
    }

    /// 失败动作 = 重启（延迟 5s；reset_period 1d）——「服务崩溃→SCM
    /// 自动重启」闭环的开关面
    pub fn set_restart_on_failure(&self) -> Result<(), String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let mut action = ScAction {
            action: SC_ACTION_RESTART,
            delay: 5000,
        };
        let mut fail = ServiceFailureActionsW {
            reset_period: 86400,
            reboot_msg: ptr::null_mut(),
            command: ptr::null_mut(),
            actions: 1,
            action_array: &mut action,
        };
        let ok = unsafe {
            (fns.change_service_config2)(
                self.handle,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                &mut fail as *mut _ as *mut c_void,
            )
        };
        if ok == 0 {
            Err(format!(
                "ChangeServiceConfig2W(failure, {}) err={}",
                self.name,
                unsafe { GetLastError() }
            ))
        } else {
            Ok(())
        }
    }

    /// 标记删除（句柄全关 + 进程退出后名号消失）
    pub fn delete(&self) -> Result<(), String> {
        let fns = advapi32().as_ref().map_err(|e| e.clone())?;
        let ok = unsafe { (fns.delete_service)(self.handle) };
        if ok == 0 {
            Err(format!("DeleteService({}) err={}", self.name, unsafe {
                GetLastError()
            }))
        } else {
            Ok(())
        }
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if let Ok(fns) = advapi32() {
            if !self.handle.is_null() {
                unsafe { (fns.close_service_handle)(self.handle) };
            }
        }
    }
}

// —— 服务端 ——

/// 服务运行上下文（服务线程递给 body）
pub struct ServiceRun {
    /// STOP/SHUTDOWN 控制置位；body 与主循环据此退出
    pub stop: Arc<AtomicBool>,
    /// StartServiceW 传参（argv[1..]）；SCM 崩溃重启=空
    pub args: Vec<String>,
}

type ServiceBody = Box<dyn FnOnce(&ServiceRun) + Send>;
static RUN: OnceLock<Mutex<Option<ServiceBody>>> = OnceLock::new();
static STOP_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// 服务端入口：注册单服务调度表并阻塞至停止。body 在服务线程内跑
/// 一次（做恢复/装路由等工作），随后本函数空转轮询停止旗，收到
/// STOP/SHUTDOWN 后回报 STOPPED。非 SCM 上下文调用=Err（调度器起不
/// 来，err 1063）。
pub fn run_service(name: &str, body: ServiceBody) -> Result<(), String> {
    let fns = advapi32().as_ref().map_err(|e| e.clone())?;
    if RUN.get().is_some() {
        return Err("run_service: already initialized".into());
    }
    let _ = RUN.set(Mutex::new(Some(body)));
    let _ = STOP_FLAG.set(Arc::new(AtomicBool::new(false)));

    // 名串必须活过调度器调用——绑定而非临时（table 持指针）
    let name_w = wide(name);
    let mut table = [
        ServiceTableEntryW {
            name: name_w.as_ptr(),
            service_main: Some(service_main),
        },
        ServiceTableEntryW {
            name: ptr::null(),
            service_main: None,
        },
    ];
    let ok = unsafe { (fns.start_service_ctrl_dispatcher)(table.as_mut_ptr()) };
    if ok == 0 {
        Err(format!("StartServiceCtrlDispatcherW err={}", unsafe {
            GetLastError()
        }))
    } else {
        Ok(())
    }
}

/// SERVICE_MAIN：登记 handler（须首做）→ START_PENDING → RUNNING →
/// 跑 body → 等停止旗 → STOPPED。argv[0]=服务名（登记用），argv[1..]
/// =StartServiceW 传参。
unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    let fns = match advapi32() {
        Ok(f) => *f,
        Err(_) => return,
    };
    let utf16 = |p: *const u16| -> String {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    };
    let svc_name = if !argv.is_null() && argc >= 1 && !(*argv).is_null() {
        utf16(*argv)
    } else {
        "rillane-svc".to_string()
    };
    let mut args = Vec::new();
    if !argv.is_null() {
        for i in 1..argc as isize {
            let p = *argv.offset(i);
            if p.is_null() {
                break;
            }
            args.push(utf16(p));
        }
    }

    let stop = STOP_FLAG
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let name_w = wide(&svc_name);
    let handle = (fns.register_service_ctrl_handler)(name_w.as_ptr(), handler_ex, ptr::null_mut());
    if handle.is_null() {
        return;
    }
    let mut st = ServiceStatus {
        service_type: SERVICE_WIN32_OWN_PROCESS,
        current_state: SERVICE_START_PENDING,
        controls_accepted: 0,
        win32_exit_code: NO_ERROR,
        service_specific_exit_code: 0,
        check_point: 0,
        wait_hint: 5000,
    };
    (fns.set_service_status)(handle, &mut st);
    st.current_state = SERVICE_RUNNING;
    st.controls_accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    (fns.set_service_status)(handle, &mut st);

    // body 一次（恢复/装路由），随后空转等停
    let body = RUN
        .get()
        .and_then(|r| r.lock().ok().and_then(|mut g| g.take()));
    let run = ServiceRun {
        stop: stop.clone(),
        args,
    };
    if let Some(b) = body {
        b(&run);
    }
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    st.current_state = SERVICE_STOPPED;
    (fns.set_service_status)(handle, &mut st);
}

/// HandlerEx：STOP/SHUTDOWN → 置停止旗；其余照常应答 NO_ERROR。
unsafe extern "system" fn handler_ex(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if let Some(s) = STOP_FLAG.get() {
                s.store(true, Ordering::SeqCst);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => NO_ERROR,
    }
}
