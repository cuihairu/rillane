# AI/LLM 应用流量识别分流（立项）

状态：**立项（2026-11-17，用户新需求）**。本批只落口径与规则模板设计，实现排后续批次；实现与验收条目为 RIL-153。

用户问题：「是不是可以对 AI 模型识别然后单独走」。答案口径：可以，但**只按域名/CDN/SNI 前缀识别，不猜流量内容**——本立项把「识别 AI 提供商流量」收敛为一组可查、可版本化的路由规则模板，命中即把该流路由到用户指定的节点/分组。

## 口径

### 识别面：域名前缀规则模板，不猜流量内容

- 覆盖常见 AI 提供商域（`openai.com` / `anthropic.com` / `claude.ai` / `gemini.google.com` / `api.kaipulse` 等）与 CDN 前缀（`domain_keyword`，如第三方承载域中的 `openai`/`anthropic` 字样）。
- **首批模板只用域名面条件**（`domain_suffix` / `domain_full` / `domain_keyword`）——现有 `MatchCondition` 匹配面即可表达，无需新引擎。
- **SNI/HTTP Host 识别依赖有界嗅探（RIL-143，未交付）**：TUN 面纯 IP 目标流在嗅探交付前不做识别（如实标注——不做 IP 段表猜测，不靠猜 IP 归属冒充识别）。
- **「openai/anthropic HTTP 头特征」为新增条件面**：现有 `MatchCondition` 没有 header 条件类型；即使将来交付，也只在 RIL-143 有界证据面内取材（不解密 HTTPS、不越认证边界、首包时间/字节有界）。排实现批次，模板首版不含。

### 走向：命中 → 用户指定 node/group

- 命中模板规则的流路由到 `target`——组名或直连节点名，与现有规则 `target` 同口径；用户自选代理组（走代理）或直连节点（走直连）。
- **不新增执行引擎**：模板落点为普通 `routing.rules` 规则面（first match wins），合入位置在泛化区域/场景规则之前（先命中先决策——AI 流量不被后面的「国内直连」类规则截走）。

### 配置面：订阅转换规则模板 + CLI 快捷命令

1. **订阅转换规则模板**：模板为 in-tree 常量（随版本发布，域名表来源可查、版本化），订阅导入/转换时按用户选择合入 `routing.rules`。**模板不远程拉取**——无供应链面。
2. **CLI 快捷命令**：`rillane ai on --proxy <group>` / `rillane ai off`（rillanectl 子命令糖）——生成/摘除模板规则。落点为**配置事务面**（RIL-073～077 提案/批准/回执链），不旁路配置代际；模板规则带可识别名前缀（`ai-`），`off` 按前缀寻址摘除，不碰用户手写规则。

### 特殊情况（如实标注）

- **流式 SSE 长连接不中断**：路由决策在建连期一次判定，既有连接不因规则/模式热更改道（SessionPin/配置代际既有口径）。模板不引入逐包重识别——无中断面。
- **websocket 面兼容**：ws 升级承载在 TCP 流内，路由面不感知应用协议；域名命中即整流（含 ws、SSE）走指定出口，无协议特判。
- **模型 API 走 UDP 的场景不存在**：主流 AI 提供商 API 均为 HTTPS/TCP。模板不涉及 UDP 面（不预留、不宣称 UDP 识别）；未来若出现 UDP 端点另行评估。

## 规则模板（YAML 样例，现有条件面表达）

```yaml
routing:
  rules:
    # RIL-153 AI/LLM 提供商识别模板（域名面首版；target 由用户指定）
    # 规则名带 ai- 前缀：CLI on/off 按前缀寻址合入/摘除。
    - name: ai-openai
      target: ai-proxy                # 用户自选：代理组名或直连节点名
      matches:
        - type: any
          conditions:
            - type: domain_suffix
              values: [openai.com, oaistatic.com, oaiusercontent.com]
            - type: domain_keyword
              values: [openai]        # CDN 前缀面（第三方承载域含 openai 字样）
    - name: ai-anthropic
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_suffix
              values: [anthropic.com, claude.ai]
            - type: domain_keyword
              values: [anthropic]
    - name: ai-gemini
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_full
              values: [gemini.google.com, aistudio.google.com]
    - name: ai-other
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_full
              values: [api.kaipulse.com]   # 示例：自有/小众端点按需补 full/suffix
```

规则内多条件为 AND，`any` 内为 OR——四条规则按 first-match-wins 依次评估，命中的 `reason` 即规则名（诊断面可读，逐提供商可分辨）。

## 实现边界（后续批次）

- 模板常量与合入/摘除逻辑（订阅转换面 + rillanectl `ai` 子命令）；
- 合入位置保证（泛化区域规则之前）与幂等（重复 `on` 不产生重复规则）；
- SNI/HTTP Host 识别面依赖 RIL-143 交付后接入（新增条件类型走同一条立项纪律：先落口径再实现）；
- 验收锚点：模板往返（合入→导出→回读零损失）、on/off 幂等、target 指向不存在组时配置校验拒绝（现有引用图校验即拦截）、SSE/ws 长连接在规则热更下不断流。
