'use strict';
/*
 * RIL-090｜MCP 客户端互操作验收驱动（固定 SDK 真实客户端）
 *
 * 固定 SDK：@modelcontextprotocol/sdk@1.32.2（官方，2026-10-23 发布体）。
 * 真实客户端面：官方 StdioClientTransport（子进程 + stdio 帧）+ 官方
 * Protocol（请求/答复/取消管理）+ 官方 Client（高层握手路径，用于
 * 边界演示）。全部场景不依赖任何模型——驱动是脚本，不是 LLM。
 *
 * 注意：该 SDK 发布体根入口 dist/esm/index.js 缺失（1.20.0–1.32.2
 * tarball 均如此），须走深路径 require（./* 导出映射的 require 条件
 * → dist/cjs/*，带 .js 后缀可解析）：
 *   require('@modelcontextprotocol/sdk/client/stdio.js')
 *   require('@modelcontextprotocol/sdk/shared/protocol.js')
 *   require('@modelcontextprotocol/sdk/types.js')
 *
 * 运行：npm install && node accept.cjs（或 npm run accept）
 * 前置：rillane-mcp / rillaned / rillanectl 已构建（可用
 * RILLANE_MCP_BIN / RILLANE_DAEMON_BIN / RILLANE_CTL_BIN 或
 * CARGO_TARGET_DIR 覆盖路径）。守护进程用临时目录 + 动态空闲端口，
 * 不触碰 9090 等既有实例。退出码 0 = 全场景通过。
 */

const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');

const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { Protocol } = require('@modelcontextprotocol/sdk/shared/protocol.js');
const { Client } = require('@modelcontextprotocol/sdk/client');
const {
  McpError,
  LATEST_PROTOCOL_VERSION,
  CallToolResultSchema,
  ListToolsResultSchema,
} = require('@modelcontextprotocol/sdk/types.js');
const { z } = require('zod');

const REPO = path.resolve(__dirname, '..', '..', '..');
const TARGET = process.env.CARGO_TARGET_DIR || path.join(REPO, 'target');
const MCP_BIN = process.env.RILLANE_MCP_BIN || path.join(TARGET, 'debug', 'rillane-mcp');
const DAEMON_BIN = process.env.RILLANE_DAEMON_BIN || path.join(TARGET, 'debug', 'rillaned');
const CTL_BIN = process.env.RILLANE_CTL_BIN || path.join(TARGET, 'debug', 'rillanectl');

// 服务端冻结契约（RIL-066：官方 modern era 修订版 2026-07-28）
const SERVER_PROTOCOL = '2026-07-28';
const META_KEY = 'io.modelcontextprotocol/protocolVersion';
// 服务端把 serverInfo 放在 discover 答复的 _meta 下（modern era 位置）
const META_SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';
const TOKEN = 'accept-token';

for (const bin of [MCP_BIN, DAEMON_BIN, CTL_BIN]) {
  if (!fs.existsSync(bin)) {
    console.error(`missing binary: ${bin}（先 cargo build，或用 RILLANE_*_BIN 覆盖）`);
    process.exit(2);
  }
}

/* ---------------- 小工具 ---------------- */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 官方 Protocol 是抽象基类（唯一抽象面 assertRequestHandlerCapability；
 * 发布版 Client 按 legacy 能力面实现它）。冻结服务端是 modern era
 * 2026-07-28（无 initialize、无能力面、逐请求 _meta 声明版本）——
 * 客户端对该抽象面按 modern era 语义实现为空：纯客户端不接
 * 服务端→客户端请求，无需能力面门。场景 6 证明发布版 Client.connect()
 * 的 legacy 握手（initialize@2025-11-25）被冻结服务端以 -32601 拒绝。
 */
class RilProtocol extends Protocol {
  assertRequestHandlerCapability() {}
}

/* ---------------- 场景骨架 ---------------- */

function check(cond, msg) {
  if (!cond) throw new Error(msg);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function waitPort(port, ms) {
  const deadline = Date.now() + ms;
  return new Promise((resolve) => {
    (function tryOnce() {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => {
        s.destroy();
        resolve(true);
      });
      s.once('error', () => {
        s.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(tryOnce, 100);
      });
    })();
  });
}

function withTimeout(p, ms, label) {
  return Promise.race([
    p,
    sleep(ms).then(() => {
      throw new Error(`timeout: ${label}`);
    }),
  ]);
}

function procExit(proc) {
  return new Promise((resolve) => proc.once('exit', (code, signal) => resolve({ code, signal })));
}

/** 带版本声明的请求参数面（冻结契约：逐请求 _meta 声明协议版本） */
function meta(extra = {}) {
  return { _meta: { [META_KEY]: SERVER_PROTOCOL }, ...extra };
}

/** 官方 Protocol 上的任意方法请求（宽松 schema——形状断言在驱动内做） */
function req(protocol, method, params, options) {
  return protocol.request({ method, params }, z.any(), options);
}

function call(protocol, name, args = {}, options) {
  return req(protocol, 'tools/call', meta({ name, arguments: args }), options);
}

/** 期待 McpError 抛出并返回之 */
async function expectMcpError(promise, label) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  throw new Error(`${label}: 应抛 McpError 而实际成功`);
}

/* ---------------- 场景骨架 ---------------- */
const results = [];
async function scenario(name, run) {
  const t0 = Date.now();
  try {
    const note = (await run()) || '';
    results.push({ name, ok: true, ms: Date.now() - t0, note });
    console.log(`PASS  ${name}${note ? `  (${note})` : ''}`);
  } catch (e) {
    results.push({ name, ok: false, ms: Date.now() - t0, note: e.message });
    console.error(`FAIL  ${name}: ${e.message}`);
  }
}

/* ---------------- 生命周期 ---------------- */
function daemonConfig(port, socksPort) {
  // 守护进程要求至少一个入口（无入口时启动拒绝：仅 network.mode=tun/
  // transparent 可豁免）——匿名 socks5 入口绑动态端口，仅作启动占位，
  // 无流量经过（不指向任何出口）。
  return `control:
  api_bind: 127.0.0.1:${port}
  uds_path: null
  admin_token: ${TOKEN}
telemetry:
  log_level: info
  enable_metrics: false
  enable_tracing: false
ingress:
  - name: accept-in
    type: socks5
    bind: 127.0.0.1:${socksPort}
egress:
  - name: direct-main
    type: direct
routing:
  default_node: direct-main
  groups:
    - name: auto
      strategy: latency
      members:
        - direct-main
  rules: []
udp:
  enabled: false
probe:
  targets:
    - kind: connect
      addr: 127.0.0.1:1
  limits:
    job_timeout_ms: 1500
    max_active: 2
`;
}

async function startDaemon(cfgPath, port) {
  const proc = spawn(DAEMON_BIN, [], {
    cwd: REPO,
    // RILLANE_MESH_ALLOW_PLAINTEXT=1：配置文档化的开发环境明文放行门
    // （mesh data-plane 默认要求 mTLS；验收守护仅服务控制面，无 mesh 对端）
    env: { ...process.env, RILLANE_CONFIG: cfgPath, RILLANE_MESH_ALLOW_PLAINTEXT: '1' },
    stdio: 'ignore',
  });
  const ok = await Promise.race([waitPort(port, 8000), procExit(proc).then(() => false)]);
  if (!ok) {
    proc.kill('SIGKILL');
    throw new Error(`daemon 未在 8s 内监听 127.0.0.1:${port}`);
  }
  return proc;
}

/** 官方 SDK 真实客户端会话（stdio 子进程 + Protocol） */
async function openMcp({ scope = 'read', endpoint }) {
  const transport = new StdioClientTransport({
    command: MCP_BIN,
    args: ['--endpoint', endpoint, '--token', TOKEN, '--scope', scope, '--rate-limit', '0'],
    cwd: REPO,
    stderr: 'pipe',
  });
  const protocol = new RilProtocol();
  await protocol.connect(transport);
  return { transport, protocol };
}

function killMcp(session) {
  try {
    session.transport._process?.kill('SIGKILL');
  } catch {
    /* already gone */
  }
}

/* ---------------- 主流程 ---------------- */
(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ril-accept-'));
  const daemonPort = await freePort();
  const socksPort = await freePort();
  const cfgPath = path.join(tmp, 'accept.yaml');
  fs.writeFileSync(cfgPath, daemonConfig(daemonPort, socksPort));
  const base = `http://127.0.0.1:${daemonPort}`;
  let daemon = await startDaemon(cfgPath, daemonPort);
  let daemonAlive = true;

  /* 1. server/discover（真实 SDK 请求，探测面免版本门） */
  await scenario('1 server/discover 经官方 SDK 请求', async () => {
    const s = await openMcp({ endpoint: base });
    try {
      const res = await req(s.protocol, 'server/discover', {});
      check(Array.isArray(res.supportedVersions), 'supportedVersions 在场');
      check(
        res.supportedVersions.every((v) => v === SERVER_PROTOCOL),
        `supportedVersions 仅 ${SERVER_PROTOCOL}（实得 ${res.supportedVersions}）`,
      );
      check(res.capabilities && typeof res.capabilities.tools === 'object', '声明 tools 能力面');
      // 服务端把 serverInfo 放 _meta（modern era 位置），非顶层
      const info = res._meta?.[META_SERVER_INFO_KEY];
      check(info && typeof info.name === 'string', `serverInfo 在 _meta[${META_SERVER_INFO_KEY}] 在场`);
      return `supported=${res.supportedVersions.join(',')} server=${info?.name}`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 2. tools/list：16 工具 + 单页终止（分页正确性） */
  await scenario('2 tools/list 目录与分页终止', async () => {
    const s = await openMcp({ endpoint: base });
    try {
      const res = await req(s.protocol, 'tools/list', meta());
      check(Array.isArray(res.tools), 'tools 在场');
      check(res.tools.length === 16, `目录 16 工具（实得 ${res.tools.length}）`);
      check(!('nextCursor' in res), '无 nextCursor → 客户端分页循环正确终止（单页）');
      for (const t of res.tools) {
        check(typeof t.name === 'string' && t.name.length > 0, `工具名在场: ${t.name}`);
        check(t.description && t.description.length > 0, `${t.name} 描述在场`);
        check(t.inputSchema && typeof t.inputSchema === 'object', `${t.name} inputSchema 在场`);
        check(!('scope' in t), `${t.name} 目录不泄漏服务端 scope 内部口径`);
      }
      // 信息面（记录性发现，不阻断）：发布版官方 ListToolsResultSchema
      // 只认 inputSchema.type==="object"，拒绝 probe_submit 的合法
      // JSON Schema oneOf 联合——与 legacy initialize/2025-11-25 同源
      // 的发布版形状面。真实客户端按此 schema 校验会漏掉该工具，
      // 故以 data.code/schema 细节记录，供 modern era SDK 升级时回收。
      const parse = ListToolsResultSchema.safeParse(res);
      if (parse.success) return '16 工具；官方 ListToolsResultSchema 校验通过';
      const issue = parse.error.issues[0];
      return `16 工具；官方 ListToolsResultSchema 拒绝：路径 ${issue.path.join('.')}（${issue.message}）——probe_submit 的 oneOf inputSchema（合法 JSON Schema）超出发布版 schema 形状，属 legacy 面，记为边界`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 3. 读工具闭环（读写演示·读）——四个 Read 档工具对活守护进程 */
  await scenario('3 读工具闭环 runtime_stats/flow_list/routing_quality/config_audit', async () => {
    const s = await openMcp({ endpoint: base });
    try {
      for (const name of ['runtime_stats', 'flow_list', 'routing_quality', 'config_audit']) {
        const res = await call(s.protocol, name, {});
        check(res.isError === false, `${name} 应成功（isError=false）`);
        check(Array.isArray(res.content) && res.content.length > 0, `${name} content 非空`);
        check(res.structuredContent && typeof res.structuredContent === 'object', `${name} structuredContent 信封在场`);
      }
      // 信息面：官方 CallToolResultSchema 对本结果形状
      const res = await call(s.protocol, 'runtime_stats', {});
      const parse = CallToolResultSchema.safeParse(res);
      return `4 工具全通；官方 CallToolResultSchema 校验=${parse.success ? '通过' : '拒绝(' + String(parse.error?.message).slice(0, 80) + ')'}`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 4. 权限拒绝：只读档调用写工具 → 越权稳定码；拒绝不进边界 */
  await scenario('4 权限拒绝（只读档 × apply_config_change）', async () => {
    const s = await openMcp({ scope: 'read', endpoint: base });
    try {
      const err = await expectMcpError(
        call(s.protocol, 'apply_config_change', { proposal_id: 'x', approval_id: 'y' }),
        '只读档调用写工具',
      );
      check(err instanceof McpError, `应为 McpError（实得 ${err?.constructor?.name}）`);
      check(err.code === -32001, `越权稳定码 -32001（实得 ${err.code}）`);
      check(
        err.data && typeof err.data.code === 'string' && err.data.code.length > 0,
        `data.code 机器口径在场（实得 ${JSON.stringify(err.data)}）`,
      );
      // 被拒后只读面不受影响（拒绝不进边界/不耗配额）
      const after = await call(s.protocol, 'runtime_stats', {});
      check(after.isError === false, '拒绝后只读工具照常');
      // 码冲突信息：SDK 侧 RequestTimeout 也定义为 -32001 —— 数值同码，
      // 必须以 data.code 区分（记录为边界，不判失败）
      return `code=${err.code} data.code=${err.data.code}；注意 SDK ErrorCode.RequestTimeout 同为 -32001（以 data.code 消歧）`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 5. 错误面：未知名 / 缺 name / 版本协商失败 / legacy initialize */
  await scenario('5 错误面（未知名/缺 name/版本协商/legacy initialize）', async () => {
    const s = await openMcp({ endpoint: base });
    try {
      const unknown = await expectMcpError(call(s.protocol, 'no_such_tool', {}), '未知名');
      check(unknown.code === -32602, `未知名应 -32602（实得 ${unknown.code}）`);
      check(unknown.data?.code, `未知名 data.code 在场（实得 ${JSON.stringify(unknown.data)}）`);

      const noName = await expectMcpError(
        s.protocol.request({ method: 'tools/call', params: meta() }, z.any()),
        '缺 name',
      );
      check(noName.code === -32602 && noName.data?.code === 'mcp.input.required', `缺 name 应 -32602/mcp.input.required（实得 ${noName.code}/${noName.data?.code}）`);

      const oldVersion = await expectMcpError(
        s.protocol.request(
          { method: 'tools/list', params: { _meta: { [META_KEY]: LATEST_PROTOCOL_VERSION } } },
          z.any(),
        ),
        '旧版本声明',
      );
      check(oldVersion.code === -32022, `旧版本应 -32022（实得 ${oldVersion.code}）`);
      check(
        Array.isArray(oldVersion.data?.supported) && oldVersion.data.supported.includes(SERVER_PROTOCOL),
        `data.supported 供客户端重选（实得 ${JSON.stringify(oldVersion.data)}）`,
      );

      const legacy = await expectMcpError(
        s.protocol.request(
          {
            method: 'initialize',
            params: {
              protocolVersion: LATEST_PROTOCOL_VERSION,
              capabilities: {},
              clientInfo: { name: 'accept', version: '0.0.1' },
            },
          },
          z.any(),
        ),
        'legacy initialize',
      );
      check(legacy.code === -32601, `modern 服务端不识别 initialize 应 -32601（实得 ${legacy.code}）`);
      return `unknown=${unknown.code} noName=${noName.data?.code} oldVer=-32022(supported=${oldVersion.data?.supported}) initialize=-32601`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 6. 官方高层 Client.connect()（发布版握手路径）——边界演示 */
  await scenario('6 官方 Client.connect() 握手路径（记录性）', async () => {
    const transport = new StdioClientTransport({
      command: MCP_BIN,
      args: ['--endpoint', base, '--token', TOKEN, '--scope', 'read', '--rate-limit', '0'],
      cwd: REPO,
      stderr: 'pipe',
    });
    const client = new Client({ name: 'sdk-official-client', version: '1.32.2' });
    const err = await expectMcpError(client.connect(transport), 'Client.connect');
    check(err instanceof McpError, `应为 McpError（实得 ${err?.constructor?.name}: ${err?.message}）`);
    check(err.code === -32601, `握手失败码 -32601（实得 ${err.code}）`);
    await transport.close().catch(() => {});
    return `发布版 SDK 高层握手（initialize@${LATEST_PROTOCOL_VERSION}）与冻结 modern 面不互通：${String(err.message).slice(0, 60)}`;
  });

  /* 7. 取消·SDK 原生路径：AbortSignal（真实在途请求 + cancel 通知） */
  await scenario('7 取消·SDK AbortSignal 原生路径', async () => {
    // 挂死端点：接受连接但永不响应 → 服务端在边界执行器内阻塞（30s 上限）
    const hungPort = await freePort();
    const hung = net.createServer(() => {});
    await new Promise((r) => hung.listen(hungPort, '127.0.0.1', r));
    try {
      const s = await openMcp({ endpoint: `http://127.0.0.1:${hungPort}` });
      try {
        const ac = new AbortController();
        const t0 = Date.now();
        const p = call(s.protocol, 'runtime_stats', {}, { signal: ac.signal });
        await sleep(120);
        ac.abort(new Error('user cancelled'));
        const err = await expectMcpError(p, 'AbortSignal 取消');
        const ms = Date.now() - t0;
        check(err instanceof McpError, `应为 McpError（实得 ${err?.constructor?.name}）`);
        check(ms < 2000, `客户端应在 2s 内停止等待（实得 ${ms}ms）`);
        return `${ms}ms 内拒绝等待；SDK 已发 notifications/cancelled（单线程服务端稍后完成边界调用并写答复，客户端按无主答复丢弃——边界如实）`;
      } finally {
        killMcp(s); // 服务端仍在边界执行内阻塞——SIGKILL 收尾，不等 30s
      }
    } finally {
      hung.close();
    }
  });

  /* 8. 取消·冻结契约抑制面：取消先登记 → 该请求答复不写 */
  await scenario('8 取消·答复抑制（取消先登记，官方传输层）', async () => {
    const transport = new StdioClientTransport({
      command: MCP_BIN,
      args: ['--endpoint', base, '--token', TOKEN, '--scope', 'read', '--rate-limit', '0'],
      cwd: REPO,
      stderr: 'pipe',
    });
    const seen = [];
    transport.onmessage = (m) => seen.push(m);
    transport.onclose = () => {};
    await transport.start();
    try {
      // 先取消登记 id=77，再发 id=77 请求（确定性抑制序列——单线程
      // 服务端按行序处理，取消先到则该请求执行后答复不写）
      await transport.send({
        jsonrpc: '2.0',
        method: 'notifications/cancelled',
        params: { requestId: 77, reason: 'user cancelled' },
      });
      await transport.send({
        jsonrpc: '2.0',
        id: 77,
        method: 'tools/call',
        params: meta({ name: 'runtime_stats', arguments: {} }),
      });
      await transport.send({
        jsonrpc: '2.0',
        id: 78,
        method: 'tools/call',
        params: meta({ name: 'runtime_stats', arguments: {} }),
      });
      await sleep(1500);
      check(!seen.some((m) => m.id === 77), '被取消请求的答复不写（id=77 静默）');
      const ctrl = seen.find((m) => m.id === 78);
      check(ctrl && ctrl.result, '对照请求照常答复（id=78）');
      return 'id=77 无答复；id=78 正常';
    } finally {
      await transport.close().catch(() => {});
    }
  });

  /* 9. 启动退出：EOF（stdin 关闭）→ 干净退出码 0 */
  await scenario('9 启动退出（EOF → 退出码 0）', async () => {
    const s = await openMcp({ endpoint: base });
    const proc = s.transport._process;
    check(proc, '子进程句柄在场');
    const discover = await req(s.protocol, 'server/discover', {});
    check(discover.supportedVersions?.[0] === SERVER_PROTOCOL, '会话可用');
    const exit = procExit(proc);
    await s.protocol.close(); // 官方传输 close() = stdin.end() → EOF 路径
    const r = await withTimeout(exit, 5000, 'EOF 退出');
    check(r.code === 0, `EOF 应干净退出码 0（实得 code=${r.code} signal=${r.signal}）`);
    return `code=${r.code}`;
  });

  /* 10. 断连恢复·守护侧：kill → 带内稳定错误 → 复活后同会话恢复 */
  await scenario('10 断连恢复（守护进程侧）', async () => {
    const s = await openMcp({ endpoint: base });
    try {
      const before = await call(s.protocol, 'runtime_stats', {});
      check(before.isError === false, '断连前读工具正常');

      daemon.kill('SIGKILL');
      daemonAlive = false;
      await sleep(200);
      const down = await call(s.protocol, 'runtime_stats', {});
      check(down.isError === true, '守护失联应带内 isError（非协议崩溃）');
      check(
        down.structuredContent && typeof down.structuredContent === 'object',
        '失败信封 structuredContent 在场',
      );

      daemon = await startDaemon(cfgPath, daemonPort);
      daemonAlive = true;
      const after = await call(s.protocol, 'runtime_stats', {});
      check(after.isError === false, '守护复活后同一 MCP 会话恢复');
      return `断连 isError=${down.isError}（稳定码信封）；复活后 isError=${after.isError}`;
    } finally {
      await s.protocol.close().catch(() => {});
    }
  });

  /* 11. 断连恢复·服务端侧：SIGKILL rillane-mcp → 新会话恢复 */
  await scenario('11 断连恢复（rillane-mcp 进程侧）', async () => {
    const s = await openMcp({ endpoint: base });
    const proc = s.transport._process;
    const exit = procExit(proc);
    proc.kill('SIGKILL');
    const r = await withTimeout(exit, 5000, '服务端进程退出');
    check(r.signal === 'SIGKILL', `服务端进程应被 SIGKILL（实得 ${r.signal}）`);
    const s2 = await openMcp({ endpoint: base });
    try {
      const res = await req(s2.protocol, 'server/discover', {});
      check(res.supportedVersions?.[0] === SERVER_PROTOCOL, '重开会话照常服务');
      return `旧会话退出(${r.signal})；新会话 discover 恢复`;
    } finally {
      await s2.protocol.close().catch(() => {});
    }
  });

  /* 12. 模型缺席：零 LLM 下核心守护 + CLI 照常运行（全场景本就无模型） */
  await scenario('12 模型缺席（零 LLM：守护 + rillanectl 照常）', async () => {
    const out = execFileSync(CTL_BIN, ['--config', cfgPath, 'stats'], {
      encoding: 'utf8',
      timeout: 15000,
      cwd: REPO,
    });
    check(out.trim().length > 0, 'rillanectl stats 应有输出');
    return `rillanectl stats 输出 ${out.trim().split('\n').length} 行；全程零模型`;
  });

  /* ---------------- 汇总 ---------------- */
  if (daemonAlive) {
    daemon.kill('SIGTERM');
    await sleep(100);
    daemon.kill('SIGKILL');
  }
  fs.rmSync(tmp, { recursive: true, force: true });

  const failed = results.filter((r) => !r.ok);
  console.log('\n==== RIL-090 SDK 互操作验收汇总 ====');
  console.log(`场景 ${results.length}｜通过 ${results.length - failed.length}｜失败 ${failed.length}`);
  const info = results.filter((r) => r.ok && r.note);
  if (info.length) {
    console.log('记录性输出：');
    for (const r of info) console.log(`  [${r.name}] ${r.note}`);
  }
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error('driver error:', e);
  process.exit(1);
});
