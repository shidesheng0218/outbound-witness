# Outbound Witness

> **本地优先、零遥测的 AI 编程环境出站行为见证工具**

[![Rust 1.70+](https://img.shields.io/badge/Rust-1.70%2B-orange)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Status: Controlled Session Alpha](https://img.shields.io/badge/Status-Controlled%20Session%20Alpha-yellow)](#current-status)

**Outbound Witness** 是一个为 AI 编程 Agent（Claude Code、Cursor、Kimi Code 等）和开发者工具设计的出站行为监测系统。它不声称"完全阻止任何恶意软件"，而是把**正常用户权限下的隐蔽或过度数据收集变成可见、可解释、可授权、可阻断、可举证**。

---

## 🎯 核心价值主张

| 维度 | 能力 | 例子 |
|------|------|------|
| **可见** | 知道哪个进程、向哪个目标、发送了多少数据 | `claude-dev` → `api.openai.com` 发送 2.3MB |
| **可解释** | 知道哪些文件访问触发了风险 | 读取 `.env` + 连接陌生域名 → 高风险 |
| **可授权** | 授权绑定进程、版本、目标、目录范围、有效期 | 仅允许 `v1.2.3` 连接 `api.openai.com:443`，6 小时有效 |
| **可阻断** | 严格模式下阻断未授权的出站连接 | 任何未预授权的 HTTPS 目标都被拦截 |
| **可举证** | 导出不含文件正文的本地审计记录，签名可验证 | Ed25519 签名 + 可选 Sigstore 透明日志 |

---

## 🏗️ 架构概览

```
┌─────────────────────────────────────────────────────┐
│          宿主工作区 (Host Workspace)                 │
│  - 源码、配置、凭据（不复制到 Session）               │
└────────────────┬────────────────────────────────────┘
                 │
      ┌──────────┴──────────┐
      │ Session Snapshot    │
      │ (隔离副本)          │
      └────────┬────────────┘
               │
      ┌────────┴────────────────────────────────────────┐
      │                                                 │
      ▼                                                 ▼
┌─────────────────┐                          ┌──────────────────┐
│ Agent Container │                          │ Proxy Container  │
│ (限制：        │                          │ (凭据持有者:    │
│  ← DNS 封闭    │◄──HTTP 代理(本地)─────────┤  - 验证证书      │
│  ← 只读根FS    │                          │  - 拦截 HTTPS   │
│  ← no privs)   │                          │  - 注入凭据      │
└────────┬────────┘                          │  - 记录请求)     │
         │                                  └──────────────────┘
         │ 文件读写
         │ (Delta tracking)
         ▼
    ┌──────────────────┐
    │ Audit Record     │
    │ (证据):          │
    │ - 文件事件       │
    │ - 网络事件       │
    │ - 风险分数       │
    │ - 授权决策       │
    │ - Ed25519 签名   │
    └──────────────────┘
```

**核心隔离策略**：
- 代理容器持有凭据，Agent 看不到
- Agent 所有流量必须经过代理
- 文件改动由 Session 副本隔离
- 审计记录哈希链不可伪造（内嵌签名）

---

## 🔐 风险评估引擎

Outbound Witness 使用**多维度评分**而不是二元"允许/拒绝"。高风险信号包括：

| 信号 | 分数 | 触发条件 |
|------|------|---------|
| 敏感路径访问 | +50 | 读取 `.env`, `.ssh`, `.git`, 浏览器数据 |
| 批量文件读取 | +20 | 短时间内读 2+ 个文件 |
| 归档创建 | +30 | ZIP/TAR/7Z 等压缩文件被创建 |
| 首次目标域名 | +15 | 连接之前未见过的域名 |
| 大流量上传 | +10 | 单次请求 >5MB |
| **高风险阈值** | **≥70** | 触发阻断或告警 |

**例子**：

```
场景 1: 正常 Git push
- 读 .git/ 目录 → +50
- 连接 github.com（常见） → +0
- 发送 1MB → +0
= 总分 50 (ALLOW)

场景 2: 隐蔽数据收集
- 读 .env → +50
- 读 .git/ → +50
- 连接陌生 exfil.com → +15
- 发送 20MB → +10
= 总分 125 (BLOCK 严格模式 / ALERT 观察模式)
```

---

## 📦 二种工作模式

### Observe 模式 (观察)
- 所有请求**放行**，但记录高风险信号
- 用于学习和基线建立
- 输出：ALERT（告警），带分数和解释

```bash
$ outbound-witness demo --mode observe
risk_score: 50
signals: [敏感路径(+50)]
decision: ALERT
```

### Strict 模式 (严格)
- 未预授权的高风险请求**阻断**
- 用户可交互式批准或拒绝
- 输出：BLOCK（阻断）或 ALLOW（已授权）

```bash
$ outbound-witness demo --mode strict
risk_score: 75
signals: [敏感路径(+50), 首次目标(+15), 大流量(+10)]
decision: BLOCK ❌
等待用户批准... (120 秒超时)
→ approve --host api.openai.com:443 --ttl 3600
→ 下次同主机请求自动放行 (1 小时内)
```

---

## 🛡️ 受控 Session：隔离 + 审计

### Session 生命周期

```
1. 准备 (Prepare)
   ├─ 创建工作区快照 (CoW + 差异追踪)
   ├─ 排除凭据 (.env, .ssh, .aws, etc.)
   └─ 构建代理镜像

2. 启动 (Start)
   ├─ 拉起 Agent 容器 (只读根 FS, cap-drop)
   ├─ 拉起 Proxy 容器 (持有凭据)
   ├─ 注入代理环境变量 & DNS
   └─ 等待业务进程启动

3. 运行 (Running)
   ├─ Agent: 执行用户命令
   ├─ Proxy: 拦截 HTTPS CONNECT
   │   ├─ 评估风险
   │   ├─ 匹配预授权策略
   │   ├─ 暂停等待 (120 秒)
   │   └─ 放行或拒绝
   └─ 审计: 记录文件 + 网络事件

4. 收集 (Collect)
   ├─ 等待 Agent 完成
   ├─ 计算工作区 diff (SHA-256)
   ├─ 读取所有代理请求
   └─ 构建 Witness 事件链

5. 导出 (Export)
   ├─ 验证完整性 (哈希链 + 封条)
   ├─ Ed25519 签名
   ├─ 可选: 发布到 Sigstore Rekor
   └─ 输出 audit.json (可验证)

6. 回写 (Writeback)
   ├─ 用户显式选择要回写的文件
   ├─ 校验宿主文件未被外部修改
   ├─ 原子替换 (临时文件 + rename)
   └─ 旧 diff 作废 (防重复应用)
```

### 凭据隔离的关键

**传统方式**（不安全）：
```
agent 容器
├─ export AWS_ACCESS_KEY=sk-xxx  ← 密钥进入 agent！
└─ agent 读取密钥，可以直接调用 AWS
   （如果 agent 被攻破，密钥泄露）
```

**Outbound Witness 方式**（安全）：
```
proxy 容器
├─ export AWS_ACCESS_KEY=sk-xxx  ← 密钥在代理
└─ 接收来自 agent 的 http://proxy:8080/aws 请求
   ├─ 使用自己的密钥向上游 AWS 发起 TLS
   ├─ 返回结果给 agent
   └─ agent 永远看不到密钥！

agent 容器
├─ export OW_BROKER_AWS_BASE_URL=http://proxy:8080/aws
└─ 调用代理，代理返回结果
   （即使 agent 被攻破，也只能看到代理地址）
```

---

## 🔍 审计与验证

### 哈希链 + 完整性封条

每条审计记录的签名过程：

```
audit record N
    │
    ├─ hash(record_N) = hash_N
    │
    ├─ hash(hash_N-1 || hash_N) = hash_chain_N
    │    ↑ 前序链：改动任一记录都会破坏整条链
    │
    ├─ 记录数 + 最终哈希 = 完整性封条
    │    ↑ 发现尾部截断
    │
    └─ Ed25519_sign(all_records) = signature
         ↑ 证明来源（需要可信公钥）
```

**验证步骤**：

```bash
# 1. 独立验证完整性（不需信任来源）
$ outbound-witness verify audit.json
✓ 哈希链有效
✓ 完整性封条有效 (125 条记录)
✓ 内嵌签名有效 (公钥: 3f7a...)
→ 证实：文件未被篡改，记录完整，来源一致

# 2. 验证来源（需要信任的公钥）
$ outbound-witness verify audit.json \
    --pubkey ~/trusted-keys/alice.pub
✓ 签名由 alice@example.com 的密钥产生
→ 证实：审计由可信来源生成

# 3. 可选：验证 Sigstore 时间戳
$ outbound-witness verify audit.json \
    --rekor-entry uuid-from-export
✓ Rekor 条目 uuid-xxx 于 2025-01-13T10:30:00Z 记录
✓ Merkle 树包含证明有效
→ 证实：此导出曾在公开透明日志中存在
```

---

## 🚀 快速开始

### 前置条件

- **Rust 1.70+**：`rustc --version`
- **Docker Desktop / Colima**：用于 Session 容器
- **Node.js 18+**（可选）：用于桌面 UI

### 安装与构建

```bash
# 克隆并构建
git clone https://github.com/shidesheng0218/outbound-witness.git
cd outbound-witness

# 运行测试
cargo test --workspace

# 构建 CLI
cargo build --release

# 构建代理镜像（Session 必需）
docker build -t outbound-witness/proxy:local -f proxy-image/Dockerfile .

# 可选：安装 CLI 到 PATH
cp target/release/outbound-witness /usr/local/bin/
```

### 基础演示

```bash
# 1. 检查工具状态
outbound-witness status

# 2. 观察模式演示
outbound-witness demo --mode observe
# 输出: ALERT, 分数 50+

# 3. 严格模式演示
outbound-witness demo --mode strict
# 输出: BLOCK, 等待批准

# 4. 评估自定义事件
outbound-witness evaluate fixtures/sensitive-batch-upload.json --mode strict
# 输出: BLOCK, 分数 125+
```

### 受控 Session（完整流程）

```bash
# 1. 检查 Docker 就绪
outbound-witness doctor runtime
# 输出: ✓ Docker daemon 运行
#       ✓ 代理镜像可用

# 2. 启动 Session，限定允许的域名
outbound-witness session start \
    --workspace . \
    --mode strict \
    --image my-agent:v1 \
    --allow-host api.openai.com:443 \
    --allow-host api.anthropic.com:443 \
    -- python3 agent.py

# 3. 在另一个终端监听状态
outbound-witness session status
# 输出: session-abc123: RUNNING (agent pid 4521)
#       pending_requests: 1 (openai.com:443)
#       elapsed: 23s

# 4. 批准请求（交互式或命令行）
outbound-witness session approve session-abc123 \
    --request req-001 \
    --host api.openai.com \
    --port 443 \
    --ttl 3600

# 或拒绝
outbound-witness session deny session-abc123 --request req-001

# 5. 预授权策略（避免逐条批准）
outbound-witness session preauth add session-abc123 \
    --host '*.github.com' \
    --port 443 \
    --ttl 7200  # 2 小时

# 6. Session 结束后查看 diff
outbound-witness session diff session-abc123
# 输出: modified:  src/main.rs (before: abc..., after: def...)
#       new:       output.txt
#       deleted:   temp.log

# 7. 显式选择回写的文件
outbound-witness session apply session-abc123 \
    --path src/main.rs \
    --path output.txt
# ✓ 原子写入，宿主文件保持安全

# 8. 导出完整审计
outbound-witness session export session-abc123 \
    --output audit-session-abc123.json

# 9. 独立验证
outbound-witness verify audit-session-abc123.json
# ✓ 哈希链有效, 完整性封条有效, 签名有效
```

---

## 🔌 高级用法

### 凭据管理：Broker 模式

在不暴露密钥的前提下让 Agent 访问受保护资源：

**1. 准备凭据路由配置** (`config/broker-policies.yaml`)：

```yaml
routes:
  - route: "openai"
    upstream_host: "api.openai.com"
    upstream_port: 443
    secret_env: "OPENAI_API_KEY"
    allowed_methods: ["POST"]
    allowed_paths: ["/v1/chat/completions", "/v1/embeddings"]
    max_bytes_per_hour: 104857600  # 100 MB/小时
    max_requests_per_minute: 60    # 60 req/分钟
    
  - route: "github"
    upstream_host: "github.com"
    upstream_port: 443
    secret_file: "/proxy-state/github-token"
    token_command: "gh auth token"  # 宿主机获取短期 token
    allowed_methods: ["GET", "POST"]
    allowed_paths: ["/api/v3/repos/", "/repos/"]
    redact_response_body: false
```

**2. 启动 Session 时注入凭据路由**：

```bash
export OPENAI_API_KEY="sk-..."
outbound-witness session start \
    --workspace . \
    --mode strict \
    --image my-agent:v1 \
    --credential-routes config/broker-policies.yaml \
    -- python3 agent.py
```

**3. Agent 使用代理而非直接密钥**：

```python
# agent 看不到 OPENAI_API_KEY
import os
print(os.getenv("OPENAI_API_KEY"))  # None

# agent 只能通过代理
broker_url = os.getenv("OW_BROKER_OPENAI_BASE_URL")
# "http://proxy:8080/openai"

response = requests.post(
    f"{broker_url}/v1/chat/completions",
    json={"model": "gpt-4", ...}
)
# 代理用自己的 OPENAI_API_KEY 调用上游
# 返回结果给 agent
```

**4. 审计日志记录授权决策**：

```json
{
  "request": {
    "host": "api.openai.com",
    "method": "POST",
    "path": "/v1/chat/completions",
    "bytes_sent": 2048
  },
  "policy_decision": {
    "route": "openai",
    "allowed": true,
    "reason": "method POST in [POST], path /v1/chat/completions in allowed_paths",
    "budget_status": "50/3600 bytes used this hour"
  }
}
```

---

## 📊 当前状态 (v0.2.0 Controlled Session Alpha)

### ✅ 已实现

| 功能 | 状态 | 说明 |
|------|------|------|
| 风险评估引擎 | ✅ | 多维度评分 + 可解释规则 |
| Observe/Strict 模式 | ✅ | 灵活的执行策略 |
| 授权管理 | ✅ | 进程 SHA-256 + 域名 + 端口 + 路径 + TTL |
| 哈希链审计 | ✅ | 前序链 + 完整性封条 + Ed25519 签名 |
| 受控 Session | ✅ | 快照 + 代理 + 隔离 + diff + 原子写回 |
| HTTPS CONNECT 代理 | ✅ | 拦截、暂停、批准、拒绝、超时 |
| 凭据隔离 Broker | ✅ | 密钥不进 Agent，代理持有 |
| CLI + JSON 导出 | ✅ | 完整命令行接口 + 可验证导出 |
| 容器安全参数 | ✅ | cap-drop, no-new-privileges, 只读根FS |
| 桌面 UI (Tauri) | ✅ | 演示 + Session 控制 + 实时批准 |
| **事件采集框架** | ✅ | **新增**: 可插拔文件/进程观测器 |
| **透明日志集成** | ✅ | **新增**: Sigstore Rekor 支持 |
| **CLI Wrapper** | ✅ | **新增**: 无需 `session start` 的透明启用 |
| **策略驱动 Broker** | ✅ | **新增**: 方法/路径/预算/响应脱敏 |

### 📋 下一阶段 (Roadmap)

| 功能 | 预计 | 说明 |
|------|------|------|
| Linux eBPF 事件采集 | Q1 2025 | 内核级文件/进程观测 |
| macOS EndpointSecurity 适配 | Q2 2025 | ESF 文件事件 |
| Windows ETW 适配 | Q2 2025 | ETW 文件/进程事件 |
| IDE 集成 (VS Code/Cursor) | Q1 2025 | 透明 wrapper + 审批界面 |
| 完整 Broker 策略配置 | Q1 2025 | YAML/TOML 支持 + 可视化 |
| 安装器 & 权限引导 | Q2 2025 | macOS/Windows 平台包 |
| 第三方审计 | Q3 2025 | 安全审查 + 合规验证 |

### ⚠️ 已知限制

- **HTTPS 不解密**：隐私设计选择，无法看到请求/响应内容
- **整机覆盖仅限 Session**：后续 eBPF/ESF 可扩展到整机
- **容器隔离 vs gVisor**：使用标准 Docker，非微 VM（可选升级）
- **平台支持**：Linux 完整，macOS/Windows 原生适配待完成

---

## 🔐 隐私与安全承诺

### 隐私边界

```
✅ 默认不解密 HTTPS
✅ 默认不上传遥测
✅ 默认不保存文件正文
✅ 审计日志本地存储（可选发布到透明日志）
✅ 快照隔离工作区（凭据不复制）

⚠️ 代理进程持有凭据（新的信任边界）
⚠️ session.json 包含完整启动命令
⚠️ 不防御内核级恶意程序
```

### 对手模型

**防护对象**：
- 开发者在本地运行的 AI Agent（如 Claude Code）
- 恶意或异常的第三方依赖、脚本
- 过度收集数据的工具或库

**防护范围**：
- 隐蔽的网络出站
- 敏感文件的无授权访问
- 凭据的意外泄露

**不防护对象**：
- 获得 root/admin/kernel 权限的恶意程序
- 物理层攻击或侧信道攻击
- 已编译进二进制的恶意行为

---

## 📁 项目结构

```
outbound-witness/
├── crates/
│   ├── core/
│   │   ├── src/
│   │   │   ├── lib.rs              # 核心数据结构 + 风险评估
│   │   │   ├── events.rs           # 事件采集框架 [NEW]
│   │   │   ├── transparency.rs     # 透明日志集成 [NEW]
│   │   │   ├── session.rs          # Session 生命周期
│   │   │   └── workspace.rs        # 工作区快照 & diff
│   │   └── tests/
│   │
│   ├── cli/
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── lib.rs
│   │   │   ├── session_runtime.rs  # CLI 命令实现
│   │   │   ├── signing.rs          # 签名与验证
│   │   │   └── wrapper.rs          # 透明 wrapper [NEW]
│   │   └── tests/
│   │
│   └── proxy/
│       ├── src/
│       │   ├── lib.rs
│       │   ├── broker.rs           # HTTPS 代理实现
│       │   └── policy.rs           # 策略驱动网关 [NEW]
│       └── tests/
│
├── desktop/
│   ├── src-tauri/                  # Rust Tauri 后端
│   └── src/                        # React 前端
│
├── proxy-image/
│   └── Dockerfile                  # 代理容器镜像
│
├── config/
│   ├── default-rules.json          # 默认风险规则
│   └── credential-routes.example.json
│
├── fixtures/                       # 测试场景
│   ├── sensitive-batch-upload.json
│   └── benign-git-push.json
│
├── docs/
│   ├── architecture.md
│   ├── session-security.md
│   └── cli-reference.md
│
├── OPTIMIZATION_ROADMAP.md         # 2025 优化路线图
└── README.md (本文件)
```

---

## 🧪 测试与质量保证

### 单元测试

```bash
# 运行所有测试
cargo test --workspace

# 特定测试
cargo test --package outbound-witness-core -- risk_scoring
cargo test --package outbound-witness-proxy -- broker_policy
```

### 集成测试

```bash
# 演示场景
cargo run -- demo --mode observe
cargo run -- demo --mode strict --export demo.json

# 会话测试（需要 Docker）
cargo run -- session start \
    --workspace fixtures/test-workspace \
    --mode strict \
    -- bash fixtures/test-script.sh
```

### 代码质量

```bash
# Lint 检查
cargo clippy --all-targets --all-features

# 格式检查
cargo fmt --check

# 安全审计
cargo audit
```

---

## 🤝 贡献指南

我们欢迎以下类型的贡献：

1. **事件采集后端**：Linux eBPF / macOS ESF / Windows ETW
2. **IDE 集成**：VS Code、Cursor、JetBrains 扩展
3. **文档与示例**：用例、配置模板、教程
4. **安全审查**：代码审计、威胁建模、测试场景
5. **本地化**：文档翻译、用户界面本地化

详见 [CONTRIBUTING.md](CONTRIBUTING.md)（待补充）

---

## 📖 完整文档

- **[架构设计](docs/architecture.md)**：系统设计、隔离策略、数据流
- **[Session 安全模型](docs/session-security.md)**：快照、隔离、原子性保证
- **[CLI 参考](docs/cli-reference.md)**：所有命令详解、参数说明
- **[优化路线图](OPTIMIZATION_ROADMAP.md)**：2025 年开发计划、集成策略

---

## 📊 基准与对标

### 能力矩阵

| 工具 | 本地优先 | 可观测 | 可隔离 | 可授权 | 可验证 | 凭据隔离 |
|------|---------|--------|--------|--------|--------|---------|
| **Outbound Witness** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Little Snitch | ✅ | ✅ | ⚠️ | ✅ | ❌ | ❌ |
| OpenSnitch | ✅ | ✅ | ⚠️ | ✅ | ❌ | ❌ |
| E2B Sandbox | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ |
| gVisor | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ |
| LiteLLM Gateway | ❌ | ✅ | ❌ | ✅ | ⚠️ | ✅ |

### 差异化定位

> **为 AI 编程环境设计的本地可验证出站证据 + 凭据隔离层**

与竞品的主要区别：
- **vs Little Snitch**：着重可验证性 + 凭据隔离（非仅拦截）
- **vs E2B**：本地工作，无需外部服务；完整凭据治理
- **vs LiteLLM**：深度隔离 + 证据链（非仅网关）
- **vs Falco/Tetragon**：应用级、本地即时反馈（非仅后端审计）

---

## ⚖️ 许可证

Apache License 2.0 — 详见 [LICENSE](LICENSE)

## 🙌 致谢

特别感谢：
- Rust 社区的 tokio、serde、ring 等生态
- Docker 社区的容器安全最佳实践
- Sigstore 项目的透明日志基础设施
- SLSA 框架的供应链安全思想

---

## 📞 联系与支持

- **GitHub Issues**：[报告 bug、提交功能请求](https://github.com/shidesheng0218/outbound-witness/issues)
- **讨论**：[特性讨论、设计建议](https://github.com/shidesheng0218/outbound-witness/discussions)
- **安全披露**：请勿公开发布；邮件至 security@outboundwitness.local

---

**Outbound Witness** — 让 AI 编程透明、可控、可信。
