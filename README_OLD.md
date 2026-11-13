# Outbound Witness / 出站见证

一个完全本地、零遥测的开源出站行为见证工具，面向个人开发者和 AI 编程工具用户。

它的目标不是声称“任何恶意软件都无法外传”，而是把正常用户权限下的隐蔽或过度收集变成：

1. 可见：知道哪个进程、向哪个目标、发送了多少数据。
2. 可解释：知道哪些文件访问行为触发了风险。
3. 可授权：授权绑定进程、版本、目标域名、目录范围和有效期。
4. 可阻断：严格模式下阻断高风险出站事件。
5. 可举证：导出不含文件正文的本地审计记录。

## 当前状态

当前版本是 v0.2.0 受控 Session Alpha：

- Rust 核心已实现事件模型、敏感路径/批量读取/归档/首次域名/大流量规则。这套打分只作用于 `evaluate` 喂入的事件，不会单独放行或阻断 Session 里的网络连接。
- `evaluate` 的观察模式返回 `Alert`，严格模式返回 `Block`。Session 严格模式是另一条规则：未批准的 HTTPS CONNECT 会被拒绝，即使风险分低于 70。
- 离线授权会校验可执行文件内容哈希、目标域名、目标端口、目录范围和 RFC3339 过期时间；过期时间无法解析时授权不匹配。旧版未记录端口的授权文件按"任意端口"兼容处理。
- 可执行文件哈希指文件内容的 SHA-256，不是路径；事件未提供且文件无法读取时，授权不匹配（失败关闭）。
- 审计记录采用前序哈希链，导出 JSON，不存文件正文。`session export` 会在导出前重新计算链，并写入**完整性封条**（记录数 + 链根哈希），然后签名。`outbound-witness verify <audit.json>` 可独立校验链、封条和内嵌签名：改动、重排或删除**中间**记录都会失败。需要注意，**纯哈希链无法发现尾部截断**；封条 + 内嵌签名能发现没有私钥的截断，而只有 `verify --pubkey <可信公钥>` 才能证明来源。
- 导出时还会用本机 Ed25519 密钥签名（首次导出自动生成，私钥以 0600 存于状态目录）。`outbound-witness pubkey` 打印公钥，`verify --pubkey <公钥或文件>` 可进一步确认**来源**。注意：**公钥必须来自你自己信任的渠道**——文件内嵌的公钥只是方便对照，本身不构成证据。不提供 `--pubkey` 时 verify 只报告"完整性封条有效（内嵌签名）"，不会声称来源可信；任何能生成密钥对的人都能伪造一条自洽记录。审计导出使用严格 schema：文档中出现未知字段会被拒绝，不会被静默忽略。旧版本导出的 Session 记录没有封条，当前 `verify` 会拒绝，请用旧版本校验或重新导出。
- CLI 提供状态查看、演示事件和审计导出。
- 通过 `outbound-witness session start` 创建隔离工作区副本，默认不复制 `.env`、`.git`、`.ssh`、浏览器配置，以及 `.aws`、`.kube`、`.docker`、`.gnupg`、`.npmrc`、`.netrc`、`.pypirc`、`.git-credentials`、`.pgpass` 和 `id_rsa`/`id_ed25519`/`id_ecdsa` 这类凭据存储与私钥。
- Session 的代码改动只能落在隔离副本；必须先运行 `session diff` 查看，再以 `--path` 明确选择写回宿主工作区，且写回只能在 Session 结束后进行。
- 写回前会核对宿主文件是否仍等于 diff 记录的 `before_sha256`、快照文件是否仍等于 `after_sha256`，并拒绝经过符号链接的路径；写入使用临时文件 + 原子替换，任一项不一致都会中止整次写回，宿主文件保持原样。每次写回后旧 diff 作废，必须重新运行 `session diff` 才能再次 apply。
- 导出前会严格读取全部代理请求记录；记录缺失或损坏时导出失败，而不是静默省略证据后仍生成签名文件。
- 本地 CONNECT proxy 不解密 HTTPS；严格模式对未授权 HTTPS 目标默认暂停最多 120 秒，用户可用 `approve` 或 `deny` 写入本地控制文件。`once` 只放行这一次请求，`host` 放行该主机直到 `--ttl`（不填 TTL 则持续到会话结束），`session` 放行该主机直到会话结束且不看 TTL。批准同时绑定该请求的目标端口，摘要不一致或端口不一致则代理拒绝放行；`host` 与 `session` 只覆盖同一主机与同一端口，旧版缺少端口字段的授权按任意端口兼容。桌面审批默认改为 `once`，避免误点一次就放行整个域名。
- 代理默认拒绝解析到环回、私网、链路本地、CGNAT、文档地址或云元数据地址的 CONNECT 目标，并直接连接已解析的 IP，避免批准后发生 DNS 重绑定。确实需要内网目标时可显式设置 `OW_PROXY_ALLOW_PRIVATE=1`，这会关闭该防护，不建议日常使用。
- 代理有资源上限：每个 Session 最多 256 个并发连接、5000 条请求记录，请求头和请求体读取都有超时；超限返回 503/429，避免被攻破的 agent 耗尽代理线程或磁盘。proxy 容器以状态目录属主身份运行（Unix），启用 `--cap-drop ALL`、`no-new-privileges`、只读根文件系统、pids/memory 限制；agent 容器使用 `--dns 127.0.0.1`，尽量避免外部 DNS 解析成为绕过代理的旁路（是否完全阻断取决于 Docker 的 DNS 实现，应在目标 runtime 实测）；需要外部解析时用 `OW_AGENT_DNS=<server>` 覆盖，`OW_AGENT_DNS=none` 恢复 Docker 默认。
- Session 按启动时取证的镜像内容摘要运行，而不是可变的 tag；`token_command` 有 60 秒超时，凭证写入路由声明的 `secret_file`。`session export` 会在签名前从 `proxy-state/requests` 补建缺失的 CONNECT witness，即使进程被中断也能导出已有证据。
- `session start` 未显式指定 `--mode` 时默认 strict；需要观察模式必须写 `--mode observe`。桌面启动固定使用 strict。
- 凭据可以完全不进入 agent 容器：用 `--credential-routes` 指向一份路由文件后，代理用**自身进程环境**里的密钥向上游发起独立的、经过证书校验的 HTTPS 调用并注入指定头部。agent 只拿到 `http://proxy:8080/<route>` 这个地址（以及一个不含密钥的 `OW_BROKER_<ROUTE>_BASE_URL` 变量），拿不到密钥本身。因为 agent 从不与该上游建立 TLS，所以这不涉及解密 agent 的 HTTPS；代价是代理进程成为持有可用凭据的新信任边界。
  凭据来源有两种，路由必须且只能声明一个：`secret_env`（代理容器环境变量）或 `secret_file`（代理状态目录内的文件，权限 0600）。声明 `secret_file` 时可再声明 `token_command`——CLI 会在**宿主机**执行它来换取短期凭据（例如云 CLI 打印临时 token），输出写入该文件。agent 容器没有该目录的任何挂载，因此无论哪种来源密钥都不会进入 agent。路由文件格式见 `config/credential-routes.example.json`。
- 预授权策略用于消除逐条审批的摩擦：启动时用可重复的 `--allow-host host:port`，或运行中用 `session preauth add <id> --host <h> --port <p> [--ttl 秒]` 声明。命中的 CONNECT 直接放行、不再暂停等待人工；规则始终绑定端口、可设 TTL、可用 `session preauth list/remove` 管理。审计会区分"预授权策略自动放行"与"人工批准"，二者不会混为一谈。
- Docker Session 使用内部网络、强制代理环境变量、`--cap-drop ALL` 和 `no-new-privileges`；不使用 privileged、host network 或 Docker socket。
- 桌面 UI 可调用 runtime 诊断、Session 启动和状态列表。
- macOS / Windows 原生网络过滤和文件事件适配目前明确标为 scaffold，尚未宣称已获得内核级拦截能力。

## 快速开始

需要 Rust 1.97+。命令行二进制名是 `outbound-witness`。若想使用短名，可自行添加 shell 别名。

```bash
cargo test --workspace
cargo run -p outbound-witness -- status
cargo run -p outbound-witness -- demo --mode observe
cargo run -p outbound-witness -- demo --mode strict --export audit-demo.json
cargo run -p outbound-witness -- evaluate fixtures/sensitive-batch-upload.json --mode strict
cargo run -p outbound-witness -- evaluate fixtures/benign-git-push.json --mode strict
cargo run -p outbound-witness -- status --json

# 受控 Session（Docker Desktop 或 Colima 已启动后）
cargo run -p outbound-witness -- doctor runtime
cargo run -p outbound-witness -- session start --workspace . --mode strict --image your-agent-image:tag --allow-host api.example.com:443 -- your-agent-command
cargo run -p outbound-witness -- session preauth list <session-id>
cargo run -p outbound-witness -- session preauth add <session-id> --host '*.github.com' --port 443 --ttl 600
cargo run -p outbound-witness -- session start --workspace . --mode strict --image your-agent-image:tag --credential-routes config/credential-routes.example.json -- your-agent-command
cargo run -p outbound-witness -- session status
cargo run -p outbound-witness -- session diff <session-id>
cargo run -p outbound-witness -- session apply <session-id> --path src/main.rs
cargo run -p outbound-witness -- session export <session-id> --output audit.json
cargo run -p outbound-witness -- verify audit.json
cargo run -p outbound-witness -- pubkey
cargo run -p outbound-witness -- verify audit.json --pubkey <对方给你的公钥>
```

严格模式的演示应输出 `BLOCK 阻断`；观察模式的同一事件应输出 `ALERT 告警`。

Session 所需的 agent 镜像由用户明确准备。工具不会自动拉取外部镜像，也不会自动构建 proxy 镜像。首次使用前，用户需在仓库根目录显式运行：

```bash
docker build -t outbound-witness/proxy:local -f proxy-image/Dockerfile .
```

## 桌面层

需要 Node.js、npm 和 Tauri 2 工具链：

```bash
cd desktop
npm install
npm run build
npm run tauri dev
```

桌面层可展示风险演示、非阻塞发起受控 Session、查看运行状态，并在 Session 运行中直接响应代理的批准/拒绝请求（绑定镜像摘要与可选 TTL）；Session 结束时通过本地事件刷新结果。系统权限申请和原生过滤器接入会在平台适配器完成后加入。

## 隐私边界

- 默认不解密 HTTPS。
- 默认不上传遥测。
- 默认不保存文件正文。
- Session 默认以工作区快照运行；写回必须由用户按路径明确批准。
- 日志只包含路径、大小、哈希、进程、目的地和策略判断。注意 `session.json` 会记录启动命令的完整参数；不要把 token 直接写在 agent 命令行里。
- 严格模式阻断网络出站，不阻断程序在本地读取或创建归档。
- 不防御已经获得管理员、内核或系统扩展权限的恶意程序。

## Benchmark

`fixtures/` 中的场景用于比较不同工具的透明度：正常 Git push、敏感文件批量外发、带用户授权的归档上传。测试重点是行为是否被解释和阻断，而不是给工具贴“恶意”标签。

## Roadmap

- [x] 可解释事件模型和风险规则
- [x] Observe / Strict 两种模式
- [x] 授权和哈希链审计
- [x] CLI 演示和 JSON 导出
- [x] 受控 Session 快照、diff、显式写回与本地审计
- [x] HTTPS CONNECT egress proxy 的暂停、批准、拒绝和超时阻断策略
- [x] Docker-compatible runtime 诊断和受限容器参数
- [x] Tauri Session 控制入口
- [ ] macOS Network Extension 适配
- [ ] macOS Endpoint Security 文件事件适配
- [ ] Windows WFP 适配
- [ ] Windows 文件事件适配
- [ ] 真实进程/连接/文件事件端到端测试
- [ ] 安装器和权限引导

## License

Apache-2.0
