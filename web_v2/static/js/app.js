/* Minimal v2 UI scaffolding (no build step). */

const API = "";

function getToken() {
  return localStorage.getItem("nexus_v2_token") || "";
}

function setToken(token) {
  if (!token) localStorage.removeItem("nexus_v2_token");
  else localStorage.setItem("nexus_v2_token", token);
  renderAuthStatus();
}

function headers() {
  const h = { "Content-Type": "application/json" };
  const token = getToken();
  if (token && token !== "auth-disabled") h["Authorization"] = `Bearer ${token}`;
  return h;
}

async function apiGet(path) {
  const resp = await fetch(`${API}${path}`, { headers: headers() });
  if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
  return await resp.json();
}

async function apiPost(path, body) {
  const resp = await fetch(`${API}${path}`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body || {}),
  });
  if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
  return await resp.json();
}

function renderAuthStatus() {
  const el = document.getElementById("auth-status");
  const token = getToken();
  el.textContent = token ? `Token set (${token.slice(0, 18)}...)` : "Not logged in.";
}

async function login() {
  const username = document.getElementById("username").value || "admin";
  const password = document.getElementById("password").value || "";
  const resp = await apiPost("/api/v2/auth/token", { username, password });
  setToken(resp.access_token || "");
}

function logout() {
  setToken("");
}

async function refreshEngagements() {
  const data = await apiGet("/api/v2/engagements?limit=200");
  const sel = document.getElementById("eng-select");
  sel.innerHTML = "";
  for (const e of data.engagements || []) {
    const opt = document.createElement("option");
    opt.value = e.id;
    opt.textContent = `${e.name} (${e.id})`;
    sel.appendChild(opt);
  }
}

async function createEngagement() {
  const name = document.getElementById("eng-name").value || "Engagement";
  const e = await apiPost("/api/v2/engagements", { name });
  await refreshEngagements();
  document.getElementById("eng-select").value = e.id;
}

function currentEngagementId() {
  const sel = document.getElementById("eng-select");
  return sel.value;
}

async function refreshScope() {
  const eid = currentEngagementId();
  if (!eid) return;
  const data = await apiGet(`/api/v2/engagements/${eid}/scope-rules?limit=500`);
  document.getElementById("scope-list").textContent = JSON.stringify(data.scope_rules || [], null, 2);
}

async function addScopeRule() {
  const eid = currentEngagementId();
  if (!eid) return;
  const type = document.getElementById("scope-type").value;
  const pattern = document.getElementById("scope-pattern").value;
  await apiPost(`/api/v2/engagements/${eid}/scope-rules`, { type, pattern, enabled: true });
  await refreshScope();
}

async function createRun() {
  const eid = currentEngagementId();
  const target = document.getElementById("run-target").value;
  const scan_mode = document.getElementById("scan-mode").value;
  const run = await apiPost(`/api/v2/engagements/${eid}/runs`, { kind: "scan", target, scan_mode });
  document.getElementById("run-created").textContent = `Run created: ${run.id}`;
  document.getElementById("run-id").value = run.id;
}

let ws = null;

function appendEventLine(line) {
  const pre = document.getElementById("events");
  pre.textContent += line + "\n";
  pre.scrollTop = pre.scrollHeight;
}

function connectWS() {
  const runId = document.getElementById("run-id").value;
  if (!runId) return;
  const token = getToken();
  const url = new URL(`/ws/v2/runs/${runId}`, window.location.origin);
  if (token) url.searchParams.set("token", token);
  ws = new WebSocket(url.toString().replace("http://", "ws://").replace("https://", "wss://"));
  ws.onmessage = (msg) => appendEventLine(msg.data);
  ws.onopen = () => appendEventLine("[ws] connected");
  ws.onclose = () => appendEventLine("[ws] closed");
  ws.onerror = () => appendEventLine("[ws] error");
}

function disconnectWS() {
  if (ws) ws.close();
  ws = null;
}

async function bootstrap() {
  renderAuthStatus();
  try { await refreshEngagements(); } catch (e) {}
}

document.getElementById("btn-login").addEventListener("click", () => login().catch(e => alert(e)));
document.getElementById("btn-logout").addEventListener("click", () => logout());
document.getElementById("btn-create-eng").addEventListener("click", () => createEngagement().catch(e => alert(e)));
document.getElementById("btn-refresh-eng").addEventListener("click", () => refreshEngagements().catch(e => alert(e)));
document.getElementById("btn-add-scope").addEventListener("click", () => addScopeRule().catch(e => alert(e)));
document.getElementById("btn-refresh-scope").addEventListener("click", () => refreshScope().catch(e => alert(e)));
document.getElementById("btn-create-run").addEventListener("click", () => createRun().catch(e => alert(e)));
document.getElementById("btn-connect").addEventListener("click", () => connectWS());
document.getElementById("btn-disconnect").addEventListener("click", () => disconnectWS());

bootstrap();

