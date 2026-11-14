import Foundation
import NetworkExtension

/// NEPacketTunnelProvider 接入 rillane-ffi 的最小通路（P3-4）。
///
/// 数据面与 Android VpnService 同形：系统 TUN fd 交给 Rust（rillane_ffi_tun_start
/// 持有并跑 ICMP echo 轮转）；TCP/UDP 真实代理路径随 P1-2 TunIngress 接入，
/// 届时 fd 持有点换 TunIngress，本类形状不变。
///
/// 构建前置（README「集成步骤」节）：
/// 1. `librillane_ffi.a/so`（aarch64-apple-ios）由 `build.sh`（macOS 侧）产出；
/// 2. bridging header 引入 `rillane_ffi.h`（crates/rillane-ffi/include/）；
/// 3. Packet Tunnel Provider extension target 声明于宿主 App。
class RillanePacketTunnelProvider: NEPacketTunnelProvider {

    /// FFI 句柄（会话生命周期内复用；0 = 未启动）
    private var ffiHandle: UnsafeMutableRawPointer? = nil

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // 1) 起完整 rillane runtime（配置经 Provider 首选项下发，App Group 共享）
        let configYaml = Self.loadConfigYaml() ?? Self.defaultConfigYaml
        guard let yaml = configYaml.cString(using: .utf8) else {
            completionHandler(NETunnelProviderError(code: .configurationInvalid)); return
        }
        guard let handle = rillane_ffi_start(yaml, yaml.count - 1) else {
            let msg = rillane_ffi_last_error().map { String(cString: $0) } ?? "unknown"
            rillane_ffi_free_string(rillane_ffi_last_error())
            NSLog("rillane runtime start failed: \(msg)")
            completionHandler(NETunnelProviderError(code: .configurationWriteFailed)); return
        }
        ffiHandle = handle

        // 2) 隧道网络设置：IPv4 10.111.0.2/24 + 测试网段路由（与 Android demo
        //    同口径——全局路由随 P1-2 TunIngress 真实代理路径落地后再开）
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.111.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.111.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.111.0.0", destinationSubnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4
        settings.mtu = 1500 as NSNumber

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self, error == nil else {
                completionHandler(error); return
            }
            // 3) fd 交接：packetFlow 的 socket fd 交 Rust（KVC 读私有 fd 是
            //    NEPacketTunnelProvider 生态的既定做法；系统撤销时以
            //    stopTunnel 收尾）
            let fd = self.packetFlow.value(forKey: "socket.fileDescriptor") as? Int32 ?? -1
            guard fd >= 0, rillane_ffi_tun_start(handle, fd) == 0 else {
                let msg = rillane_ffi_last_error().map { String(cString: $0) } ?? "unknown"
                NSLog("rillane tun start failed: \(msg)")
                completionHandler(NETunnelProviderError(code: .configurationWriteFailed)); return
            }
            NSLog("rillane tunnel up; ping 10.111.0.1 可验一轮流量")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if let handle = ffiHandle {
            rillane_ffi_stop(handle) // 内部先停 TUN 线程（fd 随之关闭）
            ffiHandle = nil
        }
        completionHandler()
    }

    // MARK: - 配置面

    /// Provider 首选项（宿主 App 经 saveProviderConfiguration 下发的 YAML）
    private static func loadConfigYaml() -> String? {
        guard let dict = UserDefaults(suiteName: "group.dev.rillane.shared")?,
              let yaml = dict["rillaneConfigYaml"] as? String else { return nil }
        return yaml
    }

    /// 兜底最小配置（与 Android assets/rillane.yaml 同形）
    private static let defaultConfigYaml = """
    control:
      api_bind: 127.0.0.1:9090
      uds_path: null
      admin_token: demo-token
    telemetry:
      log_level: info
      enable_metrics: false
      enable_tracing: false
    ingress:
      - name: socks-in
        type: socks5
        bind: 127.0.0.1:7890
    egress:
      - name: direct-main
        type: direct
    routing:
      default_node: direct-main
      groups: []
      rules: []
    """
}

/// 最小错误形（本地化描述按正式面补）
final class NETunnelProviderError: Error {
    enum Code {
        case configurationInvalid
        case configurationWriteFailed
    }
    let code: Code
    init(code: Code) { self.code = code }
}
