# 受控 Session 安全模型

## 保护承诺

Outbound Witness v0.2 强保护适用于通过 `outbound-witness session start` 启动的 CLI 工具。

- 工具只看到工作区隔离副本；默认不复制 `.env`、`.git`、`.ssh`、浏览器配置、`.outbound-witness`，以及 `.aws`、`.kube`、`.docker`、`.gnupg`、`.npmrc`、`.netrc`、`.pypirc`、`.git-credentials`、`.pgpass`、`id_rsa`/`id_ed25519`/`id_ecdsa` 这类凭据存储与私钥。
- 容器没有 privileged 权限、host network 或 Docker socket。
- Agent 容器位于 Docker 内部网络，代理加入第二条有外网路由的网络；Agent 不在该网络中。
- Agent 通过 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY` 使用本地 egress proxy。
- Proxy 只处理 HTTPS CONNECT 元数据，不解密 TLS 内容。
- 严格模式未知请求会写入 Session 的 `proxy-state/requests/`；默认 120 秒没有授权时返回 HTTP 403。拒绝依据是没有匹配的批准，不是文件风险分。
- `outbound-witness session approve` 写入的授权绑定 Session 启动时取证的 agent 镜像内容摘要（`docker image inspect .Id`）与请求的目标端口。`once` 只覆盖这一次请求；`host` 覆盖该主机与端口并遵守 `--ttl`（不填则持续到会话结束）；`session` 覆盖该主机与端口直到会话结束，忽略 TTL。代理只放行镜像摘要与端口都一致的授权；旧版缺少端口字段的授权文件按任意端口兼容。Session 按该摘要启动容器，而不是按可变 tag。
- 预授权策略（`--allow-host` 或 `session preauth add`）命中的 CONNECT 直接放行，不再等待人工审批。规则始终绑定主机与端口，可设 TTL，仅存活于该 Session 的代理状态目录。审计会明确标注"来自预授权策略（自动放行，未经人工逐条批准）"，与"来自人工批准"分开记录。
- 代理默认拒绝解析到环回、私网、链路本地、CGNAT、文档地址或云元数据地址的目标，并直接连接已解析的 IP。设置 `OW_PROXY_ALLOW_PRIVATE=1` 会关闭这一防护，只应在确实需要内网上游时使用。
- 代理每个 Session 最多 256 个并发连接、5000 条请求记录，请求头和请求体读取都有超时；超出上限返回 503/429。proxy 容器以状态目录属主身份运行（Unix），并启用 `--cap-drop ALL`、`no-new-privileges`、只读根文件系统、pids/memory 限制。
- agent 容器设置 `--dns 127.0.0.1`，尽量避免外部 DNS 解析成为绕过代理的旁路。是否完全阻断取决于 Docker 内嵌 DNS 的实现，部署时应结合实际 runtime 验证；需要外部解析时用 `OW_AGENT_DNS=<server>` 覆盖，`OW_AGENT_DNS=none` 恢复 Docker 默认。
- 宿主工作区保持不变，直到 Session 结束、用户运行 `session diff` 查看变更并执行 `outbound-witness session apply <id> --path <relative-path>`。写回前会核对宿主文件仍等于 diff 记录的 `before_sha256`、快照文件仍等于 `after_sha256`，并拒绝父级包含符号链接的路径；任一冲突都会中止整次写回。写入使用临时文件 + 原子替换，防止中断留下半截文件；每次写回后旧 diff 作废，必须重新查看才能再次 apply。

## 凭据外置（可选）

`--credential-routes` 声明的路由把密钥留在代理容器：

- agent 容器只被注入 `OW_BROKER_<ROUTE>_BASE_URL=http://proxy:8080/<route>`，不含任何密钥；
- 代理按路由声明的来源解析密钥：`secret_env`（代理容器环境变量）或 `secret_file`（代理状态目录内的文件，宿主机写入、权限 0600，agent 容器完全没有该目录的挂载）。二者必须且只能声明一个；
- 短期凭据：路由可声明 `token_command`（例如云 CLI 打印临时 token），CLI 在**宿主机**执行它，把输出写入路由声明的 `secret_file`。命令有 60 秒超时，超时会中止启动，避免挂起的云 CLI 卡住整个 Session。若同时声明 `token_ttl_secs`，会话运行期间会按该值的一半自动重新执行并覆盖文件，因此长会话不会用到过期 token。密钥始终不进入 agent 容器；
- 限流：路由可声明 `max_requests_per_minute`，超过预算的请求返回 429，避免被攻破的 agent 把凭据当作免费 API 额度；
- 代理向上游发起**独立且经过证书校验**的 HTTPS 请求，再注入 `header` 指定的头部；
- agent 从不与该上游建立 TLS，因此这不属于解密 agent 的 HTTPS；
- 代理只转发 `content-type`、`accept`、`anthropic-version`、`anthropic-beta`、`openai-beta`、`openai-organization` 这几个头部，其余（含 agent 自己塞的 `authorization`、`x-api-key`、`host`、`cookie`）一律丢弃；
- 只接受 `Content-Length` 请求体（拒绝 chunked），请求体上限 16 MiB；响应**流式转发**——响应头一到达就下发，因此 SSE 类流式接口不会被缓冲，单个请求总量上限 256 MiB。

这引入了一个新的信任边界：**代理进程持有可直接使用的凭据**。不需要该能力时不要声明路由。

## 审计证据的两个层次

`session export` 写出的 JSON 同时带**哈希链**、**完整性封条**与 **Ed25519 签名**，三者证明的事情不同：

| | 哈希链 | 封条 + 签名 |
|---|---|---|
| 证明什么 | 导出后**没有被改动、重排或删除中间记录** | 这份记录出自**持有该私钥的一方**，且尾部没有被截断 |
| 防不住什么 | 尾部截断；任何人都能为伪造事件生成一条自洽的链 | 私钥泄露，或验证者使用文件内嵌的公钥 |
| 怎么验 | `verify <file>` | `verify <file> --pubkey <可信公钥>` |

关键约束：**公钥必须来自你信任的渠道**（对方直接给你、或走你的配置管理），不能取自待验证的文件本身——否则任何人都能生成一对密钥、签一份伪造记录、再把公钥一起塞进文件，形成闭环。因此 `verify` 在未提供 `--pubkey` 时只报告"完整性封条有效（内嵌签名）"，不会声称来源可信。封条记录签名时的记录数和链根哈希，能发现没有私钥的尾部截断；但它不能替代可信公钥。

`verify` 也支持 `evaluate`/`demo --export` 生成的 `AuditLedger`（`records` 格式）：它只校验每条记录的前序哈希与内容哈希，并明确报告"该导出没有签名，无法证明来源；链本身也不能发现尾部截断"。

`session export` 会在签名前从 `proxy-state/requests/` 补建缺失的 CONNECT witness，因此即使 Session 进程被中断，已经记录的请求仍会进入导出。读取请求记录时缺失目录或损坏文件会直接导致导出失败：静默跳过证据再生成一份签名审计，会让完整性声明掩盖证据缺口。审计文档采用严格 schema，出现未知字段会被拒绝，避免未签名的附加内容混入已签名文档。

私钥存放于状态目录的 `signing-key.pk8`，权限 0600，首次导出时自动生成。它只在本机使用，不会随审计导出。

## 用户操作边界

受控 Session 不是对不可信 Docker daemon 或恶意特权容器的防御。用户不应：

- 用受控 Session 运行 `--privileged` 容器；
- 将 Docker socket、宿主根目录或未声明目录挂入 Agent；
- 使用可自行修改 Docker daemon 配置的不可信本机账号；
- 把“强保护”表述为整机任意 GUI 应用都受保护。

## 审计

每个 Session 状态保存于 `.outbound-witness/sessions/<session-id>/session.json`，其中包含快照哈希、runtime/image 标识、审批记录、diff 哈希和显式写回结果。导出 JSON/HTML 不保存文件正文。Session 结束时，每条 CONNECT 会写成一条 `WitnessEvent` 和对应评估：文件事件为空，风险分只作解释，决定仍来自代理的批准、拒绝或超时。

