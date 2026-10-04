import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./styles.css";

type DemoResult = {
  risk_score: number;
  decision: "Allow" | "Alert" | "Block";
  explanation: string;
  signals: { code: string; explanation: string }[];
};

type SessionState =
  | "Preparing"
  | "Running"
  | "WaitingApproval"
  | "Completed"
  | "Blocked"
  | "Failed";

type SessionRecord = {
  spec: { id: string; workspace: string; command: string[] };
  state: SessionState;
};

type PendingRequest = {
  session_id: string;
  session_state: SessionState;
  request_id: string;
  host: string;
  port: number;
  bytes_sent: number;
  decision: "pending" | "allowed" | "denied";
};

type SessionFinishedPayload = {
  session_id: string | null;
  success: boolean;
  output: string;
};

const STATE_LABELS: Record<SessionState, string> = {
  Preparing: "准备中",
  Running: "运行中",
  WaitingApproval: "等待授权",
  Completed: "已完成",
  Blocked: "已阻断",
  Failed: "失败",
};

const ACTIVE_STATES: SessionState[] = ["Preparing", "Running", "WaitingApproval"];

const DECISION_LABELS: Record<PendingRequest["decision"], string> = {
  pending: "等待授权",
  allowed: "已放行",
  denied: "已拒绝",
};

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("app root missing");

app.innerHTML = `
  <section class="shell">
    <header>
      <div>
        <p class="eyebrow">LOCAL · ZERO TELEMETRY</p>
        <h1>出站见证</h1>
        <p class="subtitle">看见谁在读取文件，谁在向外发出数据。</p>
      </div>
      <span class="mode">观察模式</span>
    </header>
    <section class="hero">
      <h2>先看证据，再决定是否放行。</h2>
      <p>默认不保存文件正文、不解密 HTTPS、不向云端发送遥测。</p>
      <button id="demo">运行本地风险演示</button>
    </section>
    <section id="result" class="result empty">等待本地事件……</section>
    <section class="session-card">
      <h2>受控 Session</h2>
      <p>CLI 只在隔离副本中运行；宿主工作区要到你明确 apply 后才会写回。</p>
      <label>工作区 <input id="workspace" value="." /></label>
      <label>镜像 <input id="image" value="outbound-witness/session-base:latest" /></label>
      <label>命令 <input id="command" value="example-agent inspect" /></label>
      <div class="actions"><button id="start-session">启动 Session</button><button id="refresh-status" class="secondary">刷新状态</button></div>
      <div id="session-list" class="session-list empty">尚无本地 Session。</div>
      <div id="requests" class="requests"></div>
      <pre id="session-output" class="session-output">尚未启动 Session。</pre>
    </section>
    <footer>Outbound Witness 0.2.0 · 受控 Session Alpha；系统原生过滤器接入状态会明确显示。</footer>
  </section>
`;

/**
 * Creates an element with an optional class and text. Every value that comes
 * from the Rust backend goes through textContent, never innerHTML, so a hostile
 * session id, command, hostname, or explanation cannot inject markup.
 */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function stateClass(state: SessionState): string {
  return Object.prototype.hasOwnProperty.call(STATE_LABELS, state)
    ? state.toLowerCase()
    : "unknown";
}

function decisionClass(decision: PendingRequest["decision"]): string {
  return Object.prototype.hasOwnProperty.call(DECISION_LABELS, decision)
    ? decision
    : "unknown";
}

const DEMO_DECISION_CLASSES: Record<DemoResult["decision"], string> = {
  Allow: "allow",
  Alert: "alert",
  Block: "block",
};

function demoDecisionClass(decision: DemoResult["decision"]): string {
  return Object.prototype.hasOwnProperty.call(DEMO_DECISION_CLASSES, decision)
    ? DEMO_DECISION_CLASSES[decision]
    : "unknown";
}

document.querySelector<HTMLButtonElement>("#demo")?.addEventListener("click", async () => {
  const result = document.querySelector<HTMLDivElement>("#result");
  if (!result) return;
  result.className = "result";
  result.textContent = "正在分析……";
  try {
    const demo = await invoke<DemoResult>("evaluate_demo", { mode: "strict" });
    const decision = demo.decision === "Block" ? "已阻断" : demo.decision === "Alert" ? "已告警" : "已放行";
    const score = el("div", "score");
    score.append(
      document.createTextNode("风险分数 "),
      el("strong", undefined, String(demo.risk_score)),
      document.createTextNode(" / 100")
    );
    const signals = el("ul");
    for (const signal of demo.signals) {
      const item = el("li");
      item.append(
        el("code", undefined, signal.code),
        document.createTextNode(signal.explanation)
      );
      signals.append(item);
    }
    result.replaceChildren(
      el("div", `decision ${demoDecisionClass(demo.decision)}`, decision),
      score,
      el("p", undefined, demo.explanation),
      signals
    );
  } catch {
    result.textContent = "桌面命令尚未连接；请先启动 Tauri 开发环境。";
  }
});

const sessionOutput = document.querySelector<HTMLPreElement>("#session-output");
const sessionList = document.querySelector<HTMLDivElement>("#session-list");
const requestsPanel = document.querySelector<HTMLDivElement>("#requests");
const workspaceInput = document.querySelector<HTMLInputElement>("#workspace");
const imageInput = document.querySelector<HTMLInputElement>("#image");
const commandInput = document.querySelector<HTMLInputElement>("#command");

function setOutput(text: string) {
  if (sessionOutput) sessionOutput.textContent = text;
}

let pollTimer: number | undefined;

function stopPolling() {
  if (pollTimer !== undefined) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

function startPolling() {
  stopPolling();
  void refreshSessions();
  pollTimer = window.setInterval(() => void refreshSessions(), 1000);
}

async function refreshSessions() {
  let records: SessionRecord[] = [];
  try {
    records = JSON.parse(await invoke<string>("session_status")) as SessionRecord[];
  } catch {
    return;
  }
  renderSessionList(records);
  await renderRequests();
  if (!records.some((record) => ACTIVE_STATES.includes(record.state))) {
    stopPolling();
  }
}

function renderSessionList(records: SessionRecord[]) {
  if (!sessionList) return;
  if (records.length === 0) {
    sessionList.className = "session-list empty";
    sessionList.textContent = "尚无本地 Session。";
    return;
  }
  sessionList.className = "session-list";
  sessionList.replaceChildren(
    ...records.map((record) => {
      const row = el("div", "session-row");
      row.append(
        el("code", undefined, record.spec.id),
        el("span", `pill ${stateClass(record.state)}`, STATE_LABELS[record.state] ?? "未知状态"),
        el("span", "session-cmd", record.spec.command.join(" "))
      );
      return row;
    })
  );
}

async function renderRequests() {
  if (!requestsPanel) return;
  let views: PendingRequest[] = [];
  try {
    views = JSON.parse(
      await invoke<string>("cli", { command: ["session", "requests", "--json"] })
    ) as PendingRequest[];
  } catch {
    return;
  }
  const pending = views.filter((view) => view.decision === "pending");
  if (views.length === 0) {
    requestsPanel.replaceChildren();
    return;
  }
  const header = el("div", "requests-header");
  if (pending.length > 0) {
    header.append(el("strong", undefined, `${pending.length} 个请求等待授权`));

    const scopeLabel = el("label", "inline");
    const scopeSelect = el("select");
    scopeSelect.id = "approve-scope";
    for (const option of [
      { value: "once", label: "仅此一次", selected: false },
      { value: "host", label: "整个域名", selected: true },
      { value: "session", label: "整个 Session", selected: false },
    ]) {
      const node = el("option", undefined, option.label);
      node.value = option.value;
      node.selected = option.selected;
      scopeSelect.append(node);
    }
    scopeLabel.append(document.createTextNode("范围 "), scopeSelect);

    const ttlLabel = el("label", "inline");
    const ttlInput = el("input");
    ttlInput.id = "approve-ttl";
    ttlInput.type = "number";
    ttlInput.min = "1";
    ttlInput.placeholder = "不限";
    ttlLabel.append(document.createTextNode("有效期（秒，可空） "), ttlInput);

    header.append(scopeLabel, ttlLabel);
  } else {
    header.textContent = "暂无等待授权的出站请求。";
  }

  requestsPanel.replaceChildren(
    header,
    ...views.map((view) => {
      const row = el("div", "request-row");
      row.append(
        el(
          "span",
          `pill ${decisionClass(view.decision)}`,
          DECISION_LABELS[view.decision] ?? view.decision
        ),
        el("span", "request-target", `${view.host}:${view.port}`),
        el("span", "request-meta", view.session_id)
      );
      if (view.decision === "pending") {
        const approve = el("button", "small", "批准");
        approve.addEventListener("click", () => void respond(view.request_id, "approve"));
        const deny = el("button", "small danger", "拒绝");
        deny.addEventListener("click", () => void respond(view.request_id, "deny"));
        row.append(approve, deny);
      }
      return row;
    })
  );
}

async function respond(requestId: string, action: "approve" | "deny") {
  const command = ["session", action, requestId];
  if (action === "approve") {
    const scope = document.querySelector<HTMLSelectElement>("#approve-scope")?.value ?? "once";
    const ttl = document.querySelector<HTMLInputElement>("#approve-ttl")?.value.trim();
    command.push("--scope", scope);
    if (ttl) command.push("--ttl", ttl);
  }
  try {
    const message = await invoke<string>("cli", { command });
    setOutput(message);
  } catch (error) {
    setOutput(String(error));
  }
  await refreshSessions();
}

document.querySelector<HTMLButtonElement>("#refresh-status")?.addEventListener("click", () => {
  startPolling();
});

document.querySelector<HTMLButtonElement>("#start-session")?.addEventListener("click", async () => {
  const command = commandInput?.value.trim().split(/\s+/).filter(Boolean) ?? [];
  if (!workspaceInput?.value || !imageInput?.value || command.length === 0) {
    setOutput("工作区、镜像和命令都不能为空。");
    return;
  }
  setOutput("正在准备隔离快照并启动 Session……");
  try {
    const message = await invoke<string>("session_start", {
      workspace: workspaceInput.value,
      image: imageInput.value,
      mode: "strict",
      command,
    });
    setOutput(message);
    startPolling();
  } catch (error) {
    setOutput(String(error));
  }
});

listen<SessionFinishedPayload>("session-finished", (event) => {
  stopPolling();
  const payload = event.payload;
  setOutput(
    `${payload.success ? "Session 已结束" : "Session 启动失败"}${payload.session_id ? `：${payload.session_id}` : ""}\n${payload.output}`
  );
  void refreshSessions();
}).catch(() => {
  // Event channel unavailable outside the Tauri runtime (e.g. plain browser).
});

// Show any previously completed sessions on load.
startPolling();
