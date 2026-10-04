# 受控 Session 安全模型

## 保护承诺

Outbound Witness v0.2 强保护适用于通过 `outbound-witness session start` 启动的 CLI 工具。

- 工具只看到工作区隔离副本；默认不复制 `.env`、`.git`、`.ssh`、浏览器配置、`.outbound-witness`，以及 `.aws`、`.kube`、`.docker`、`.gnupg`、`.npmrc`、`.netrc`、`.pypirc`、`.git-credentials`、`.pgpass`、`id_rsa`/`id_ed25519`/`id_ecdsa` 这类凭据存储与私钥。
- 容器没有 privileged 权限、host network 或 Docker socket。
- Agent 容器位于 Docker 内部网络，代理加入第二条有外网路由的网络；Agent 不在该网络中。
- Agent 通过 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY` 使用本地 egress proxy。
- Proxy 只处理 HTTPS CONNECT 元数据，不解密 TLS 内容。
- 严格模式未知请求会写入 Session 的 `proxy-state/requests/`；默认 120 秒没有授权时返回 HTTP 403。拒绝依据是没有匹配的批准，不是文件风险分。
- `outbound-witness session approve` 写入的授权绑定 Session 启动时取证的 agent 镜像内容摘要（`docker image inspect .Id`）与请求的目标端口。`once` 只覆盖这一次请求；`host` 覆盖该主机与端口并遵守 `--ttl`；`session` 覆盖该主机与端口直到会话结束，忽略 TTL。代理只放行镜像摘要与端口都一致的授权；旧版缺少端口字段的授权文件按任意端口兼容。
- 预授权策略（`--allow-host` 或 `session preauth add`）命中的 CONNECT 直接放行，不再等待人工审批。规则始终绑定主机与端口，可设 TTL，仅存活于该 Session 的代理状态目录。审计会明确标注"来自预授权策略（自动放行，未经人工逐条批准）"，与"来自人工批准"分开记录。
- 宿主工作区保持不变，直到用户执行 `outbound-witness session apply <id> --path <relative-path>`。写回前会核对宿主文件是否仍等于 diff 记录的 `before_sha256`，并拒绝父级包含符号链接的路径；任一冲突都会中止整次写回。

## 凭据外置（可选）

`--credential-routes` 声明的路由把密钥留在代理容器：

- agent 容器只被注入 `OW_BROKER_<ROUTE>_BASE_URL=http://proxy:8080/<route>`，不含任何密钥；
- 代理在自身进程环境里按 `secret_env` 解析密钥，向上游发起**独立且经过证书校验**的 HTTPS 请求，再注入 `header` 指定的头部；
- agent 从不与该上游建立 TLS，因此这不属于解密 agent 的 HTTPS；
- 代理只转发 `content-type`、`accept`、`anthropic-version`、`anthropic-beta`、`openai-beta`、`openai-organization` 这几个头部，其余（含 agent 自己塞的 `authorization`、`x-api-key`、`host`、`cookie`）一律丢弃；
- 只接受 `Content-Length` 请求体（拒绝 chunked），请求体上限 16 MiB；响应**流式转发**——响应头一到达就下发，因此 SSE 类流式接口不会被缓冲，单个请求总量上限 256 MiB。

这引入了一个新的信任边界：**代理进程持有可直接使用的凭据**。不需要该能力时不要声明路由。

## 用户操作边界

受控 Session 不是对不可信 Docker daemon 或恶意特权容器的防御。用户不应：

- 用受控 Session 运行 `--privileged` 容器；
- 将 Docker socket、宿主根目录或未声明目录挂入 Agent；
- 使用可自行修改 Docker daemon 配置的不可信本机账号；
- 把“强保护”表述为整机任意 GUI 应用都受保护。

## 审计

每个 Session 状态保存于 `.outbound-witness/sessions/<session-id>/session.json`，其中包含快照哈希、runtime/image 标识、审批记录、diff 哈希和显式写回结果。导出 JSON/HTML 不保存文件正文。Session 结束时，每条 CONNECT 会写成一条 `WitnessEvent` 和对应评估：文件事件为空，风险分只作解释，决定仍来自代理的批准、拒绝或超时。

