//! RIL-044 第二段：配置/秘密引用注入面契约（本地可核验面）。
//!
//! 验收条款「配置/秘密引用注入」的 FFI 半边钉法：`rillane_ffi_start_with_secrets`
//! 把 YAML 内 `${secret:<name>}` 引用经 JSON 秘密表解析后再装配 runtime，
//! 并以**真实 RFC1929 认证往返**证明注入值确实生效（对 authenticated socks5
//! 入站：正确秘密值通过认证 + echo 往返逐字节还原；错值/错用户名被拒）。
//! fail-closed 族：缺引用 / 坏引用 / 表非法 / 表漂移（未使用键）全部 NULL +
//! 稳定码点名，绝不静默替换成空串；直通 `rillane_ffi_start` 遇引用字面量
//! 拒绝并指向正确入口（引用永不落成字面密码）。
//!
//! 诚实边界：本门钉 FFI 解析半边；Kotlin 宿主半边（Keystore/Encrypted
//! 秘密来源、`startWithSecrets` 调用纪律、秘密值不进日志的运行期证明）
//! 与 RIL-043 真机面同批次，主勾选保持关闭。JNI 符号面由 jni_symbol_face
//! 恰等门覆盖（15 方法），C 头面由 contract_query_face 头门覆盖。

use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const CONTROL_PORT: u16 = 27998;
const SOCKS_PORT: u16 = 27595;
const ECHO_PORT: u16 = 27596;
// 失败族自用端口（解析失败不 bind；非递归成功样例须真起）
const CONTROL_PORT_B: u16 = 27999;
const SOCKS_PORT_B: u16 = 27597;
const ECHO_PORT_B: u16 = 27598;

const SECRET_VALUE: &str = "contract-secret-pw-9f31";

fn config_template(socks: u16, control: u16) -> String {
    format!(
        r#"
control:
  api_bind: 127.0.0.1:{control}
  uds_path: null
  admin_token: contract-token
telemetry:
  log_level: warn
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: socks-in
    type: socks5
    bind: 127.0.0.1:{socks}
    auth:
      - username: contract-user
        password: ${{secret:ingress_pw}}
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups: []
  rules: []
"#
    )
}

fn last_error() -> String {
    let raw = unsafe { rillane_ffi::rillane_ffi_last_error() };
    assert!(!raw.is_null(), "失败面必须有 last_error");
    let msg = unsafe { CStr::from_ptr(raw) }
        .to_str()
        .expect("UTF-8")
        .to_string();
    unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    msg
}

unsafe fn start_with_secrets(yaml: &str, secrets: &str) -> *mut rillane_ffi::FfiHandle {
    rillane_ffi::rillane_ffi_start_with_secrets(
        yaml.as_ptr().cast(),
        yaml.len(),
        secrets.as_ptr().cast(),
        secrets.len(),
    )
}

/// RFC1928 方法协商 + RFC1929 用户名/密码认证；返回 (流, 认证状态字节)
fn socks5_auth(port: u16, user: &str, password: &str) -> (TcpStream, u8) {
    // start 返回与入站监听就绪之间有竞态（workspace 全量并行下 start 面更慢）
    // ——有界重试只等监听就绪，超时仍具名失败
    let mut sock = None;
    for _ in 0..500 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            sock = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut sock = sock.expect("连 socks 入站（10s 内监听应就绪）");
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("读超时");
    sock.write_all(&[0x05, 0x01, 0x02]).expect("方法协商");
    let mut method = [0u8; 2];
    sock.read_exact(&mut method).expect("方法应答");
    assert_eq!(
        method,
        [0x05, 0x02],
        "入站应选 user/pass 方法（有认证配置）"
    );
    let mut auth_req = vec![0x01, user.len() as u8];
    auth_req.extend_from_slice(user.as_bytes());
    auth_req.push(password.len() as u8);
    auth_req.extend_from_slice(password.as_bytes());
    sock.write_all(&auth_req).expect("认证请求");
    let mut auth = [0u8; 2];
    sock.read_exact(&mut auth).expect("认证应答");
    assert_eq!(auth[0], 0x01, "认证子协商版本");
    (sock, auth[1])
}

/// 认证通过后的 CONNECT + echo 往返（逐字节；expect_ok=false 只读应答不断言）
fn connect_echo(sock: &mut TcpStream, echo_port: u16, expect_ok: bool) {
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).expect("connect 请求");
    let mut rep = [0u8; 10];
    sock.read_exact(&mut rep).expect("connect 应答");
    if expect_ok {
        assert_eq!(rep[1], 0x00, "CONNECT 应成功");
        sock.write_all(b"secret-echo").expect("载荷");
        let mut echo = [0u8; 11];
        sock.read_exact(&mut echo).expect("echo");
        assert_eq!(&echo, b"secret-echo", "出口往返逐字节还原");
    }
}

/// echo 监听（test A / B 各自端口，形状同 contract_query_face）
fn spawn_echo(port: u16) -> std::thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("echo 绑定");
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { break };
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).unwrap_or(0);
            let _ = sock.write_all(&buf[..n]);
            let _ = sock.flush();
        }
    })
}

// ---------------------------------------------------------------------------
// 正向面：注入值真实生效（认证往返）+ 秘密不漏查询面
// ---------------------------------------------------------------------------

/// 注入值真实生效：正确秘密值过 RFC1929 + echo 往返；错值/错用户名被拒；
/// 全查询面原始串不含秘密值、不含引用标记（秘密不漏诊断面）。
#[test]
fn secret_ref_resolution_authenticates_real_roundtrip() {
    let _echo = spawn_echo(ECHO_PORT);
    let yaml = config_template(SOCKS_PORT, CONTROL_PORT);
    let secrets = format!(r#"{{"ingress_pw":"{SECRET_VALUE}"}}"#);
    let h = unsafe { start_with_secrets(&yaml, &secrets) };
    assert!(!h.is_null(), "引用齐备应启动成功");

    // 正确秘密值：认证 0x00 + 真实 CONNECT echo 往返
    let (mut sock, status) = socks5_auth(SOCKS_PORT, "contract-user", SECRET_VALUE);
    assert_eq!(status, 0x00, "注入的秘密值应通过 RFC1929 认证");
    connect_echo(&mut sock, ECHO_PORT, true);

    // 错秘密值：认证 0x01（拒绝）——注入值确实在比对，不是匿名放行
    let (_, bad_pw) = socks5_auth(SOCKS_PORT, "contract-user", "wrong-password");
    assert_eq!(bad_pw, 0x01, "错误秘密值必须被拒（注入值真实生效）");
    let (_, bad_user) = socks5_auth(SOCKS_PORT, "nobody", SECRET_VALUE);
    assert_eq!(bad_user, 0x01, "错误用户名必须被拒");

    // 秘密不漏诊断面：全部查询原始串（不解析——任何嵌入都现形）
    for (name, raw) in [
        ("stats", unsafe { rillane_ffi::rillane_ffi_stats_json(h) }),
        ("routing", unsafe {
            rillane_ffi::rillane_ffi_routing_json(h)
        }),
        ("nodes", unsafe { rillane_ffi::rillane_ffi_nodes_json(h) }),
        ("dns_stats", unsafe {
            rillane_ffi::rillane_ffi_dns_stats_json(h)
        }),
        ("dns_resolvers", unsafe {
            rillane_ffi::rillane_ffi_dns_resolvers_json(h)
        }),
        ("flows", unsafe {
            rillane_ffi::rillane_ffi_flows_json(h, 0, 50)
        }),
    ] {
        assert!(!raw.is_null(), "{name} 查询应答非 NULL");
        let s = unsafe { CStr::from_ptr(raw) }.to_str().expect("UTF-8");
        assert!(
            !s.contains(SECRET_VALUE),
            "秘密值泄漏进 {name} 查询面——注入面不得把秘密带进诊断输出"
        );
        assert!(
            !s.contains("${secret:"),
            "引用标记残留在 {name} 查询面——解析半边未消费引用"
        );
        unsafe { rillane_ffi::rillane_ffi_free_string(raw) };
    }

    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);
}

// ---------------------------------------------------------------------------
// fail-closed 族：缺引用/坏引用/表非法/表漂移/直通误用，全部具名拒绝
// ---------------------------------------------------------------------------

/// fail-closed：缺引用/坏引用/表非法/表漂移逐一点名稳定码（本测试所有启动
/// 均在解析期拒绝，不 bind 任何端口）。
#[test]
fn unresolved_and_malformed_refs_fail_closed() {
    let yaml = config_template(SOCKS_PORT, CONTROL_PORT);
    let secrets = format!(r#"{{"ingress_pw":"{SECRET_VALUE}"}}"#);

    // 缺引用（空表）：稳定码 + 点名引用键
    let h = unsafe { start_with_secrets(&yaml, "{}") };
    assert!(h.is_null(), "缺引用必须 fail-closed");
    let err = last_error();
    assert!(
        err.contains("secret.ref.missing") && err.contains("ingress_pw"),
        "缺引用应点名稳定码与引用键，得到：{err:?}"
    );

    // 表非法：非对象 / 值非字符串 / 非法 JSON / 空指针
    for bad in ["[]", r#"{"ingress_pw":123}"#, "{not-json"] {
        let h = unsafe { start_with_secrets(&yaml, bad) };
        assert!(h.is_null(), "表非法 {bad} 必须 fail-closed");
        assert!(
            last_error().contains("secret.map.invalid"),
            "表非法应点名 secret.map.invalid：{bad}"
        );
    }
    let h = unsafe {
        rillane_ffi::rillane_ffi_start_with_secrets(
            yaml.as_ptr().cast(),
            yaml.len(),
            std::ptr::null(),
            0,
        )
    };
    assert!(h.is_null(), "secrets_json 空指针必须 fail-closed");

    // 坏引用：空名 / 缺右括号
    let no_name =
        config_template(SOCKS_PORT, CONTROL_PORT).replace("${secret:ingress_pw}", "${secret:}");
    let h = unsafe { start_with_secrets(&no_name, &secrets) };
    assert!(h.is_null(), "空引用名必须 fail-closed");
    assert!(
        last_error().contains("secret.ref.malformed"),
        "空名应点名坏引用码"
    );
    let unterminated = config_template(SOCKS_PORT, CONTROL_PORT)
        .replace("${secret:ingress_pw}", "${secret:ingress_pw");
    let h = unsafe { start_with_secrets(&unterminated, &secrets) };
    assert!(h.is_null(), "缺右括号必须 fail-closed");
    assert!(
        last_error().contains("secret.ref.malformed"),
        "缺右括号应点名坏引用码"
    );

    // 表漂移：引用名改了、表键没跟上——未提供键点名缺引用
    let renamed = config_template(SOCKS_PORT, CONTROL_PORT)
        .replace("${secret:ingress_pw}", "${secret:renamed_key}");
    let h = unsafe { start_with_secrets(&renamed, &secrets) };
    assert!(h.is_null(), "漂移配置必须 fail-closed");
    let err = last_error();
    assert!(
        err.contains("secret.ref.missing") && err.contains("renamed_key"),
        "缺新键应点名，得到：{err:?}"
    );
    // 反向漂移：表里多了模板不再引用的键——secret.map.unused 点名，不静默吞
    let stale_map = format!(r#"{{"ingress_pw":"{SECRET_VALUE}","stale_key":"v"}}"#);
    let h = unsafe { start_with_secrets(&yaml, &stale_map) };
    assert!(h.is_null(), "未使用键必须 fail-closed");
    let err = last_error();
    assert!(
        err.contains("secret.map.unused") && err.contains("stale_key"),
        "表漂移应点名 secret.map.unused 与键名，得到：{err:?}"
    );

    // 直通口误用：引用字面量进 rillane_ffi_start → 拒绝并指向正确入口
    let h = unsafe { rillane_ffi::rillane_ffi_start(yaml.as_ptr().cast(), yaml.len()) };
    assert!(h.is_null(), "直通口遇引用必须拒绝");
    let err = last_error();
    assert!(
        err.contains("secret.ref.missing") && err.contains("start_with_secrets"),
        "直通口应指向正确入口，得到：{err:?}"
    );
}

/// 非递归：替换值长得像引用也不二次展开——表只含一个键（其值恰是另一个
/// 未提供的引用字面量），若重扫则启动期就会以缺引用拒绝；启动成功 + 用
/// 该字面量过认证 = 单遍非递归的行为证明。
#[test]
fn replacement_value_is_not_rescanned() {
    let _echo = spawn_echo(ECHO_PORT_B);
    let yaml = config_template(SOCKS_PORT_B, CONTROL_PORT_B);
    let nested = r#"{"ingress_pw":"${secret:phantom_ref}"}"#;
    let h = unsafe { start_with_secrets(&yaml, nested) };
    assert!(
        !h.is_null(),
        "替换值不重扫：值里的引用字面量不得触发二次解析"
    );
    let (mut sock, status) = socks5_auth(SOCKS_PORT_B, "contract-user", "${secret:phantom_ref}");
    assert_eq!(status, 0x00, "字面量值应原样生效");
    connect_echo(&mut sock, ECHO_PORT_B, false); // 认证已证；CONNECT 面不断言
    assert_eq!(unsafe { rillane_ffi::rillane_ffi_stop(h) }, 0);
}

// ---------------------------------------------------------------------------
// 对账器自证
// ---------------------------------------------------------------------------

/// 自证：把「缺引用」与「表非法」两稳定码混同 → 本门点名（两码必须可区分，
/// 宿主按码分支）。错误表型下应报 secret.map.invalid 而非 secret.ref.missing。
#[test]
#[should_panic(expected = "稳定码混同")]
fn comparator_bites_on_token_conflation() {
    let yaml = config_template(SOCKS_PORT, CONTROL_PORT);
    let h = unsafe { start_with_secrets(&yaml, "{not-json") };
    assert!(h.is_null(), "非法表必须 fail-closed");
    let err = last_error();
    assert!(
        err.contains("secret.ref.missing"),
        "稳定码混同：非法表报了 {err:?}——应报 secret.map.invalid"
    );
}
