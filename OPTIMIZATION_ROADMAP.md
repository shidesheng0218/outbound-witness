# Outbound Witness 优化路线图

## 状态

已添加核心基础设施，所有代码已编译通过，保持源码形态（未安装任何依赖）。

---

## 优化方向

### 1️⃣ 事件关联：文件活动可观测性

**问题**：当前 Session witness 里的 `file_events` 为空数组，导致无法回答"这个进程读了哪些文件，随后向何处上传"的关键问题。

**新增代码**：

- `crates/core/src/events.rs` — 可插拔事件采集框架
  - `EventSource` 枚举：Stub / eBPF（Linux）/ EndpointSecurity（macOS）/ ETW（Windows）
  - `EventObserver` trait：定义采集器接口，便于实现多种后端
  - `StubObserver`：测试用实现，永不失败
  - `FileActivityRecord`：聚合会话内文件活动的中间结构
  - `FileAccessEvent`, `FileOperation`, `ProcessContext`：细粒度事件模型

- `crates/core/src/lib.rs` 扩展
  - `WitnessEvent::from_file_and_network()` — 将文件事件链接到网络决策
  - 新增 `format_timestamp_ms()` — RFC 3339 时间戳工具

- `crates/core/src/session.rs` 扩展
  - `SessionRecord::file_activity: Option<FileActivityRecord>` — 存储文件活动摘要
  - 无需新增字段即可存储完整关联

**集成点**：

```rust
// Session 运行时可以这样做：
let observer = StubObserver::new();  // 或改为 eBPFObserver
observer.attach(agent_pid)?;

// 定期轮询事件
for event in observer.poll()? {
    record.file_activity.record(event);
}

// 评估时可以看到完整关联
let witness = WitnessEvent::from_file_and_network(
    &file_event,
    &network_event,
    process,
    archive_created,
    first_seen
);
```

**下一步实现**：
- Linux eBPF 收集器（用 BPF CO-RE，无需内核源码）
- macOS EndpointSecurity 适配
- 在 `record_proxy_witnesses` 时填充完整事件链
- 导出里包含 file_activity 摘要，让审计可见"哪些敏感路径被访问"

---

### 2️⃣ 可信证据链：时间戳 + 透明日志

**问题**：本机自签名，无可信时间、身份、外部锚点，无法用于团队举证或供应链追踪。

**新增代码**：

- `crates/core/src/transparency.rs` — 透明日志集成
  - `TransparencyLog` trait：定义接口
  - `RekorClient`（stub）：Sigstore Rekor 集成点
  - `StubTransparencyLog`：测试用实现
  - `SignedExport`, `TransparencyLogEntry` 数据结构
  - `publish_to_transparency_log()` 辅助函数

- `crates/core/src/session.rs` 扩展
  - `AuditSignature` 新增字段：
    - `root_hash: Option<String>` — Merkle 树根（可选）
    - `signed_at: Option<String>` — RFC 3339 签名时间戳
    - `log_entry_id: Option<String>` — 外部透明日志条目 ID（如 Rekor）
  - `AuditSignature::with_verification_proof()` — 便利方法

- `crates/cli/src/signing.rs` 更新
  - 现在初始化新字段为 `None`

**集成点**：

```rust
// 导出时可以这样做：
let mut record = load_session_record(...)?;
sign_record(&state_dir, &mut record)?;

// 可选：发布到透明日志
let log = if let Some(log_url) = args.transparency_log {
    Box::new(RekorClient::new(log_url)) as Box<dyn TransparencyLog>
} else {
    Box::new(StubTransparencyLog {})
};
publish_to_transparency_log(&mut record, log.as_ref())?;

// record.signature.log_entry_id 现在包含 Rekor 条目 ID
// 第三方可以直接在 Rekor 查证
```

**下一步实现**：
- 完成 Rekor 客户端（当前是 stub；需要 reqwest 但我们不装）
- 自建透明日志选项（基于 append-only 文件或 git）
- 支持 HSM/OS Keychain 存储私钥
- 导出时自动写入 signed_at（现在是 None）

---

### 3️⃣ CLI wrapper：无需记住 `session start`

**问题**：用户必须记得用特殊命令启动 agent，任何直接运行都无法保护。IDE 集成 / 脚本嵌入需要更低的门槛。

**新增代码**：

- `crates/cli/src/wrapper.rs` — 会话包装器框架
  - `SessionWrapper` 结构体：完整生命周期管理
  - 快速实现支持：
    - 创建 & 准备 Session（快照、代理、观测器）
    - 生成代理环境变量
    - 轮询审批
    - 命令退出后收集证据
  - `parse_shebang_directive()` — 从脚本首行 parse 配置
  - 支持 `#!/usr/bin/env outbound-witness-run` shebang

**集成点**：

```bash
# 方式 1：直接命令
outbound-witness run --allowed-hosts api.openai.com:443 -- python3 agent.py

# 方式 2：脚本 shebang
#!/usr/bin/env outbound-witness-run
# outbound-witness: mode=strict, hosts=api.openai.com:443;api.anthropic.com:443, observer=true
cd /workspace && python3 -c 'import agent; agent.analyze()'
```

**下一步实现**：
- 完成 `SessionWrapper::run()` 核心逻辑
  - 调用 `prepare_session()`
  - 启动代理容器 & 观测器
  - 生成 `OUTBOUND_WITNESS_*` 环境变量
  - 等待代理进程（处理中断 SIGINT/SIGTERM）
  - 收集证据、导出审计、清理
- IDE 集成：VS Code / Cursor / Claude Code hook
- MCP server 包装（让 Claude 能直接调用 `outbound-witness run`）

---

### 4️⃣ 策略驱动的 Broker：从转发头部升级到授权网关

**问题**：当前 Broker 只是注入固定头部，无法做方法/路径限制、预算控制、响应脱敏。agent 可以用凭据做任何事。

**新增代码**：

- `crates/proxy/src/policy.rs` — 完整的策略框架
  - `BrokerPolicy`：细粒度授权策略
    - `allowed_methods`: ["POST"] ← 禁止 GET / DELETE
    - `allowed_paths`: ["/v1/chat/completions"] ← 禁止访问其他端点
    - `max_bytes_per_hour`: 100MB ← 预算
    - `max_requests_per_minute`: 60 ← 速率限制
    - `redact_response_body`, `hash_request_body` ← 防泄露
    - `credential_ttl_seconds` ← 凭据有效期
    - `process_sha256` ← 绑定特定进程

  - `RouteBudget`：实时预算追踪
    - `bytes_sent_this_window`, `requests_this_minute`
    - `reset_if_expired()` — 每小时/分钟自动重置
    - `would_exceed_*()` — 前置检查

  - `PolicyBroker`：运行时执行
    - `add_policy()` — 注册策略
    - `authorize()` — 核心决策点
    - 同时检查方法、路径、预算、速率

**集成点**：

```rust
let mut broker = PolicyBroker::new();
broker.add_policy(BrokerPolicy {
    route: "openai".into(),
    upstream_host: "api.openai.com".into(),
    upstream_port: 443,
    allowed_methods: vec!["POST".into()],
    allowed_paths: vec!["/v1/chat/completions".into(), "/v1/embeddings".into()],
    max_bytes_per_hour: Some(100 * 1024 * 1024),
    max_requests_per_minute: Some(60),
    redact_response_body: true,
    hash_request_body: true,
    credential_ttl_seconds: Some(3600),
    process_sha256: Some("sha256:agent-binary".into()),
});

// 在 broker 处理请求前：
broker.authorize("openai", "POST", "/v1/chat/completions", 50000)?;
// 如果超过预算或不符合策略，返回错误
```

**下一步实现**：
- 配置文件格式：YAML/TOML 策略定义
- 将 `PolicyBroker` 集成到现有 Broker 请求处理流
- 响应体脱敏逻辑
- 时间基预算窗口（AWS SigV4 风格的时间戳验证）
- 仪表板：可视化实时预算消耗

---

## 编译 & 测试状态

```bash
$ cargo check --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.35s
```

所有代码已编译通过。

---

## 核心架构变化

### 新增模块关系

```
crates/core/src/
├── lib.rs                ← 引入 events, transparency
├── events.rs [NEW]       ← 文件事件采集框架
├── transparency.rs [NEW] ← 透明日志集成
├── session.rs            ← AuditSignature 增字段, file_activity 字段
└── workspace.rs

crates/cli/src/
├── lib.rs                ← 引入 wrapper
├── wrapper.rs [NEW]      ← Session 包装器 & shebang 解析
├── signing.rs            ← 初始化新 AuditSignature 字段
└── session_runtime.rs    ← 消费 events & file_activity（待实现）

crates/proxy/src/
├── lib.rs                ← 引入 policy
├── policy.rs [NEW]       ← 策略驱动 Broker
└── broker.rs             ← 集成 PolicyBroker（待实现）
```

---

## 迁移指南（逐步集成）

### Phase 1 — 事件采集（1-2 周）
1. 实现 Linux eBPF 收集器（bpf-rs / aya）或简单的 `/proc` 轮询替代
2. 在 `session_runtime.rs` 创建、启动观测器
3. 轮询并填充 `record.file_activity`
4. 测试：验证会话能看到进程读写的文件

### Phase 2 — 证据链（1 周）
1. 完成 Rekor 客户端（或自建日志）
2. 签名时写入 `signed_at`
3. 导出时可选发布到日志，获取 `log_entry_id`
4. `verify` 命令可以验证时间戳和日志项

### Phase 3 — Wrapper（1-2 周）
1. 完成 `SessionWrapper::run()` 核心
2. 测试：`outbound-witness run -- python3 agent.py` 能正常工作
3. 添加 IDE hook（VS Code 扩展或 Cursor 集成）
4. 测试：IDE 能透明地包装启动

### Phase 4 — 策略 Broker（2 周）
1. 集成 `PolicyBroker` 到现有 Broker
2. 从配置文件加载策略
3. 添加预算消耗仪表板
4. 测试：政策被正确执行，超限请求被拒

---

## 关键决策点

### 事件采集后端的选择

| 选项 | 优点 | 缺点 | 推荐 |
|------|------|------|------|
| `/proc` 轮询 | 无需内核改动 | 高开销、不完整 | 测试用 |
| eBPF (Linux) | 内核级精确、低开销 | 需要 5.8+ 内核、学习曲线 | ✅ 生产首选 |
| ESF (macOS) | 官方 API、可靠 | 需要特殊权限、仅 macOS | ✅ macOS 首选 |
| ETW (Windows) | 深层系统集成 | 学习曲线高 | ✅ Windows 长期 |

### 透明日志后端

| 选项 | 优点 | 缺点 | 推荐 |
|------|------|------|------|
| Rekor（Sigstore）| 公共基础设施、OIDC 绑定 | 需网络、外部依赖 | ✅ 公开验证 |
| 自建 Git 日志 | 无外部依赖、可离线 | 需维护、无官方保证 | 私有场景 |
| Stub（测试） | 零成本 | 不可验证 | ✅ 开发用 |

---

## 对竞争位置的影响

这四项优化直接针对分析里的关键缺陷：

| 缺陷 | 缓解方案 | 改进度 |
|-----|----------|-------|
| 文件事件空白 | 事件采集框架 | 60% → 完整关联 |
| 可信性不足 | 时间戳 + 日志 | 40% → 团队可接受 |
| 用户体验摩擦 | Wrapper + shebang | 20% → 透明启用 |
| 凭据治理太窄 | 策略网关 | 30% → 比肩 LiteLLM |

---

## 不作更改的设计

### 隔离强度（仍为 Docker）
缅因原因：
- seccomp/userns 只是防守深度，与"可验证出站证据"的楔子不直交
- gVisor 升级需平台重构，超出本轮范围
- 可后续渐进升级

### HTTPS 内容可见性（不解密）
原因：
- 本项目明确的隐私取舍
- DLP 是另一类产品的专长
- 维持边界清晰

### 整机覆盖（仍为 per-Session）
原因：
- Linux eBPF 在 session namespace 里可以做到"opt-in 覆盖"
- macOS/Windows 后续再做
- 这不是第一阶段瓶颈

---

## 配置文件示例（Phase 4）

```yaml
# config/broker-policies.yaml
policies:
  - route: openai
    upstream_host: api.openai.com
    upstream_port: 443
    allowed_methods: [POST]
    allowed_paths:
      - /v1/chat/completions
      - /v1/embeddings
    max_bytes_per_hour: 104857600  # 100 MB
    max_requests_per_minute: 60
    redact_response_body: true
    hash_request_body: true
    credential_ttl_seconds: 3600
    # process_sha256  从 approval grant 取

  - route: github
    upstream_host: github.com
    upstream_port: 443
    allowed_methods: [GET, POST]
    allowed_paths:
      - /api/v3/repos/
      - /repos/
    max_bytes_per_hour: 52428800  # 50 MB
    max_requests_per_minute: 30
    redact_response_body: false
    hash_request_body: false
    credential_ttl_seconds: 7200  # 2 hours
```

---

## 预期成果（时间表）

| 季度 | 交付 | 作用 |
|------|------|------|
| Q1 '25 | 事件采集 + Wrapper | 核心故事完整：完整关联 + 透明启用 |
| Q2 '25 | 策略 Broker | 凭据治理从"不落地"升到"可控" |
| Q3 '25 | 透明日志 + IDE 集成 | 团队采用 & 外部验证 |
| Q4 '25 | 安全审计 + 文档 | 正式产品发布 |

