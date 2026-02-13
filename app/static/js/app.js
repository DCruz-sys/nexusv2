/* ═══════════════════════════════════════════════
   NexusPenTest - Main Application JavaScript
   ═══════════════════════════════════════════════ */

// ── State ──
let chatWs = null;
let chatSessionId = null;
let selectedMethodology = 'owasp';
let currentStreamMsg = null;
let activeScanWs = {};
let activeSwarmWs = {};
let toolsData = [];
let toolsTotal = 0;
let lastToolSearchController = null;
let authBootstrapPromise = null;
let suppressWsReconnect = false;
let lastAllowlistTarget = '';
let allowlistCheckTimer = null;
let authModalState = { open: false, resolve: null, tab: 'password' };
const CHAT_SESSION_STORAGE_KEY = 'nexus_chat_session_id';

function getBearerToken() {
    return localStorage.getItem('nexus_auth_token') || '';
}

function getApiKey() {
    return localStorage.getItem('nexus_api_key') || '';
}

window.setNexusToken = function (token) {
    if (token) localStorage.setItem('nexus_auth_token', token);
};

window.setNexusApiKey = function (key) {
    if (key) localStorage.setItem('nexus_api_key', key);
};

window.clearNexusToken = function () {
    localStorage.removeItem('nexus_auth_token');
};

window.clearNexusApiKey = function () {
    localStorage.removeItem('nexus_api_key');
};

function getAuthDisplayName() {
    const stored = (localStorage.getItem('nexus_auth_username') || '').trim();
    if (stored) return stored;
    const token = getBearerToken();
    if (!token) return '';
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return '';
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        return String(payload.sub || '').trim();
    } catch (_) {
        return '';
    }
}

function wsAuthQuery() {
    const token = getBearerToken();
    const apiKey = getApiKey();
    if (token) return `token=${encodeURIComponent(token)}`;
    if (apiKey) return `api_key=${encodeURIComponent(apiKey)}`;
    return '';
}

async function apiFetch(url, options = {}) {
    const { _authRetried, ...rawOptions } = options;
    const opts = { ...rawOptions, headers: { ...(rawOptions.headers || {}) } };
    const token = getBearerToken();
    const apiKey = getApiKey();
    if (token) opts.headers['Authorization'] = `Bearer ${token}`;
    if (apiKey) opts.headers['X-API-Key'] = apiKey;
    const resp = await window.fetch(url, opts);
    if (resp.status === 401 && !_authRetried && !apiKey) {
        const authOk = await ensureAuthSession({ forcePrompt: true });
        if (authOk) {
            return apiFetch(url, { ...rawOptions, _authRetried: true });
        }
    }
    return resp;
}

function updateAuthUI() {
    const el = document.getElementById('auth-user');
    if (!el) return;
    const name = getAuthDisplayName();
    if (getApiKey()) {
        el.textContent = 'API key';
        return;
    }
    el.textContent = name || (getBearerToken() ? 'Signed in' : 'Guest');
}

async function updateConnectionStatus() {
    const statusEl = document.getElementById('connection-status');
    const dot = document.querySelector('.status-dot');
    if (!statusEl || !dot) return;

    try {
        const resp = await window.fetch('/api/health', { cache: 'no-store' });
        if (!resp.ok) throw new Error('health_failed');
        const hasAuth = Boolean(getBearerToken() || getApiKey());
        statusEl.textContent = hasAuth ? 'Connected • 127.0.0.1:8000' : 'Online • auth required';
        dot.style.background = 'var(--green)';
    } catch (_) {
        statusEl.textContent = 'Offline';
        dot.style.background = 'var(--red)';
    }
}

function startHealthPolling() {
    updateAuthUI();
    updateConnectionStatus();
    setInterval(updateConnectionStatus, 8000);
}

function showAuthError(message) {
    const el = document.getElementById('auth-error');
    if (!el) return;
    el.style.display = message ? 'block' : 'none';
    el.textContent = message || '';
}

function selectAuthTab(tab) {
    authModalState.tab = tab === 'apikey' ? 'apikey' : 'password';
    const tabPw = document.getElementById('auth-tab-password');
    const tabKey = document.getElementById('auth-tab-apikey');
    const panelPw = document.getElementById('auth-panel-password');
    const panelKey = document.getElementById('auth-panel-apikey');
    if (tabPw) tabPw.classList.toggle('active', authModalState.tab === 'password');
    if (tabKey) tabKey.classList.toggle('active', authModalState.tab === 'apikey');
    if (panelPw) panelPw.style.display = authModalState.tab === 'password' ? 'block' : 'none';
    if (panelKey) panelKey.style.display = authModalState.tab === 'apikey' ? 'block' : 'none';
    showAuthError('');
}

function showAuthModal({ subtitle = 'Authentication is required.' } = {}) {
    const modal = document.getElementById('auth-modal');
    if (!modal) return Promise.resolve(null);

    modal.style.display = 'flex';
    authModalState.open = true;
    showAuthError('');
    const sub = document.getElementById('auth-modal-subtitle');
    if (sub) sub.textContent = subtitle;

    // Prefill username for convenience.
    const u = document.getElementById('auth-username');
    if (u) u.value = (localStorage.getItem('nexus_auth_username') || 'admin').trim();
    const p = document.getElementById('auth-password');
    if (p) p.value = '';
    const k = document.getElementById('auth-apikey');
    if (k) k.value = '';

    selectAuthTab('password');

    // Enter submits.
    const onKey = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            submitAuthModal();
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            hideAuthModal();
        }
    };
    modal.addEventListener('keydown', onKey, { once: true });

    return new Promise((resolve) => {
        authModalState.resolve = resolve;
        setTimeout(() => {
            if (authModalState.tab === 'password') {
                (p || u)?.focus?.();
            } else {
                k?.focus?.();
            }
        }, 50);
    });
}

function hideAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.style.display = 'none';
    authModalState.open = false;
    showAuthError('');
    if (authModalState.resolve) {
        const resolve = authModalState.resolve;
        authModalState.resolve = null;
        resolve(null);
    }
}

async function submitAuthModal() {
    if (!authModalState.resolve) return;

    if (authModalState.tab === 'apikey') {
        const apiKey = (document.getElementById('auth-apikey')?.value || '').trim();
        if (!apiKey) {
            showAuthError('API key is required.');
            return;
        }
        const resolve = authModalState.resolve;
        authModalState.resolve = null;
        hideAuthModal();
        resolve({ mode: 'apikey', apiKey });
        return;
    }

    const username = (document.getElementById('auth-username')?.value || '').trim();
    const password = (document.getElementById('auth-password')?.value || '').trim();
    if (!username) {
        showAuthError('Username is required.');
        return;
    }
    if (!password) {
        showAuthError('Password is required.');
        return;
    }

    const resolve = authModalState.resolve;
    authModalState.resolve = null;
    hideAuthModal();
    resolve({ mode: 'password', username, password });
}

async function ensureAuthSession({ forcePrompt = false } = {}) {
    if (getApiKey()) return true;
    if (!forcePrompt && getBearerToken()) return true;
    if (authBootstrapPromise) return authBootstrapPromise;

    authBootstrapPromise = (async () => {
        if (forcePrompt) {
            window.clearNexusToken();
            window.clearNexusApiKey();
        }

        const creds = await showAuthModal({
            subtitle: forcePrompt ? 'Your session expired or is invalid. Sign in again.' : 'Authentication is required.',
        });
        if (!creds) {
            showToast('Authentication cancelled.', 'error');
            return false;
        }

        if (creds.mode === 'apikey') {
            window.setNexusApiKey(creds.apiKey);
            updateAuthUI();
            showToast('API key set.', 'success');
            return true;
        }

        try {
            const resp = await window.fetch('/api/auth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: creds.username, password: creds.password }),
            });
            let data = {};
            try {
                data = await resp.json();
            } catch (_) {
                data = {};
            }
            if (!resp.ok || !data.access_token) {
                const message = data?.message || data?.detail?.message || 'Invalid credentials.';
                showToast(`Authentication failed: ${message}`, 'error');
                return false;
            }
            window.setNexusToken(data.access_token);
            localStorage.setItem('nexus_auth_username', creds.username);
            updateAuthUI();
            showToast('Authenticated successfully.', 'success');
            return true;
        } catch (err) {
            showToast(`Authentication error: ${err.message}`, 'error');
            return false;
        }
    })();

    try {
        return await authBootstrapPromise;
    } finally {
        authBootstrapPromise = null;
    }
}

// ── Init ──
document.addEventListener('DOMContentLoaded', async () => {
    const authOk = await ensureAuthSession();
    if (!authOk && !getApiKey()) {
        console.warn('Auth token/API key not configured. Use window.setNexusToken(token) or window.setNexusApiKey(key).');
    }
    initChat();
    await restoreChatHistory();
    loadDashboard();
    loadToolsCatalog();
    loadTargets(false);
    startHealthPolling();

    const targetInput = document.getElementById('scan-target');
    if (targetInput) {
        targetInput.addEventListener('input', () => scheduleAllowlistCheck(targetInput.value));
        // Initial state if prefilled (browser autofill).
        scheduleAllowlistCheck(targetInput.value);
    }

    // Chat input handlers
    const chatInput = document.getElementById('chat-input');
    chatInput.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChatMessage();
        }
    });
    chatInput.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    });

    updateAuthUI();
});

async function restoreChatHistory() {
    const sessionId = (localStorage.getItem(CHAT_SESSION_STORAGE_KEY) || '').trim();
    if (!sessionId) return;
    chatSessionId = sessionId;
    try {
        const resp = await apiFetch(`/chat/history/${encodeURIComponent(sessionId)}?limit=80`);
        if (!resp.ok) return;
        const data = await resp.json();
        const rows = Array.isArray(data.messages) ? data.messages : [];
        if (!rows.length) return;
        const msgContainer = document.getElementById('chat-messages');
        if (!msgContainer) return;
        msgContainer.innerHTML = '';
        for (const row of rows) {
            const role = String(row.role || '').toLowerCase();
            const content = String(row.content || '');
            const bubble = document.createElement('div');
            bubble.className = `chat-msg ${role === 'user' ? 'user' : 'assistant'}`;
            const body = document.createElement('div');
            if (role === 'assistant') {
                body.className = 'msg-content';
                body.innerHTML = formatMarkdown(content);
            } else {
                body.textContent = content;
            }
            bubble.appendChild(body);
            if (role !== 'user') {
                const meta = document.createElement('div');
                meta.className = 'msg-meta';
                meta.innerHTML = `<span>${escapeHtml(String(row.model_used || 'assistant'))}</span>`;
                bubble.appendChild(meta);
            }
            msgContainer.appendChild(bubble);
        }
        msgContainer.scrollTop = msgContainer.scrollHeight;
    } catch (_) {
        // Best-effort restore only.
    }
}

window.addEventListener('beforeunload', () => {
    suppressWsReconnect = true;
    Object.values(activeSwarmWs || {}).forEach((ws) => {
        try { ws.close(); } catch (_) {}
    });
});


// ══════════════════════════════════════
// Navigation
// ══════════════════════════════════════

function navigateTo(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const pageEl = document.getElementById(`page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    const navEl = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navEl) navEl.classList.add('active');

    // Load data for pages
    if (page === 'history') loadHistory();
    if (page === 'reports') loadReports();
    if (page === 'active-scans') loadActiveScans();
    if (page === 'frameworks') showFrameworkTab('owasp');
    if (page === 'tools') loadToolsCatalog();
    if (page === 'dashboard') loadDashboard();
    if (page === 'targets') loadTargets();
    if (page === 'learning') loadLearning();
    if (page === 'swarm-runs') loadSwarmRuns();
}

function logout() {
    window.clearNexusToken();
    window.clearNexusApiKey();
    localStorage.removeItem('nexus_auth_username');
    localStorage.removeItem(CHAT_SESSION_STORAGE_KEY);
    suppressWsReconnect = true;
    try { chatWs?.close?.(); } catch (_) {}
    showToast('Logged out.', 'info');
    setTimeout(() => location.reload(), 250);
}


// ══════════════════════════════════════
// WebSocket Chat
// ══════════════════════════════════════

function initChat() {
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const query = wsAuthQuery();
    const suffix = query ? `?${query}` : '';
    const persistedSession = (localStorage.getItem(CHAT_SESSION_STORAGE_KEY) || '').trim();
    if (!chatSessionId && persistedSession) {
        chatSessionId = persistedSession;
    }
    chatWs = new WebSocket(`${protocol}://${location.host}/ws/chat${suffix}`);

    chatWs.onopen = () => {
        console.log('Chat WebSocket connected');
    };

    chatWs.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleChatMessage(data);
    };

    chatWs.onclose = (evt) => {
        if (suppressWsReconnect) return;
        if (evt && (evt.code === 4401 || evt.code === 4403)) {
            showToast('WebSocket auth failed. Re-authenticating...', 'error');
            ensureAuthSession({ forcePrompt: true }).then((ok) => {
                if (ok) setTimeout(initChat, 500);
            });
            return;
        }
        console.log('Chat WebSocket closed, reconnecting in 3s...');
        setTimeout(initChat, 3000);
    };

    chatWs.onerror = (err) => {
        console.error('Chat WebSocket error:', err);
    };
}

function handleChatMessage(data) {
    const msgContainer = document.getElementById('chat-messages');

    switch (data.type) {
        case 'session':
            if (!chatSessionId) {
                chatSessionId = data.session_id;
            }
            if (chatSessionId) {
                localStorage.setItem(CHAT_SESSION_STORAGE_KEY, chatSessionId);
            }
            break;

        case 'meta':
            // Show model info badge on current stream message
            if (currentStreamMsg) {
                let meta = currentStreamMsg.querySelector('.msg-meta');
                if (!meta) {
                    meta = document.createElement('div');
                    meta.className = 'msg-meta';
                    currentStreamMsg.appendChild(meta);
                }
                const memoryInfo = data.memory_hits !== undefined ? `<span>Memory: ${data.memory_hits}</span>` : '';
                meta.innerHTML = `<span>Model: ${data.model}</span><span>Task: ${data.task_type}</span>${memoryInfo}`;
            }
            break;

        case 'stream_start':
            currentStreamMsg = document.createElement('div');
            currentStreamMsg.className = 'chat-msg assistant';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'msg-content';
            currentStreamMsg.appendChild(contentDiv);
            msgContainer.appendChild(currentStreamMsg);
            // Remove typing indicator
            const typing = msgContainer.querySelector('.typing-indicator');
            if (typing) typing.parentElement.remove();
            break;

        case 'token':
            if (currentStreamMsg) {
                const content = currentStreamMsg.querySelector('.msg-content');
                if (content) {
                    content.textContent += data.content;
                }
            }
            msgContainer.scrollTop = msgContainer.scrollHeight;
            break;

        case 'stream_end':
            if (currentStreamMsg) {
                const content = currentStreamMsg.querySelector('.msg-content');
                if (content) {
                    content.innerHTML = formatMarkdown(content.textContent);
                }
            }
            currentStreamMsg = null;
            document.getElementById('chat-send-btn').textContent = '➤';
            msgContainer.scrollTop = msgContainer.scrollHeight;
            break;

        case 'error':
            showToast(`Chat error: ${data.message}`, 'error');
            break;
    }
}

function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const msg = input.value.trim();
    if (!msg) return;
    if (!chatWs || chatWs.readyState !== WebSocket.OPEN) {
        showToast('Chat connection is not ready. Retrying...', 'error');
        initChat();
        return;
    }

    const model = document.getElementById('chat-model-select').value;
    const msgContainer = document.getElementById('chat-messages');

    // Add user message bubble
    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.innerHTML = `<div>${escapeHtml(msg)}</div><div class="msg-meta"><span>You</span>${model ? `<span>→ ${model}</span>` : '<span>Auto-Route</span>'}</div>`;
    msgContainer.appendChild(userMsg);

    // Add typing indicator
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-msg assistant';
    typingDiv.innerHTML = '<div class="typing-indicator"><span></span><span></span><span></span></div>';
    msgContainer.appendChild(typingDiv);

    msgContainer.scrollTop = msgContainer.scrollHeight;
    input.value = '';
    input.style.height = 'auto';
    document.getElementById('chat-send-btn').textContent = '⏳';

    chatWs.send(JSON.stringify({
        message: msg,
        model: model || null,
        session_id: chatSessionId,
    }));
}


// ══════════════════════════════════════
// Scanning
// ══════════════════════════════════════

function selectMethodology(el) {
    document.querySelectorAll('.method-card').forEach(c => c.classList.remove('selected'));
    el.classList.add('selected');
    selectedMethodology = el.dataset.method;
}

async function startScan() {
    const target = document.getElementById('scan-target').value.trim();
    if (!target) {
        showToast('Please enter a target URL or IP address', 'error');
        return;
    }

    let scanType = document.getElementById('scan-type').value;
    scanType = scanType === 'quick' ? 'quick' : 'full';
    const notes = (document.getElementById('scan-notes')?.value || '').trim();

    // Friendly precheck for scope issues.
    const allowInfo = await checkAllowlist(target);
    if (allowInfo && allowInfo.allowed === false) {
        showToast('Target is not allowlisted. Add it in Targets first.', 'error');
        navigateTo('targets');
        prefillTargetRule(target);
        return;
    }

    try {
        const resp = await apiFetch('/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                methodology: selectedMethodology,
                scan_type: scanType,
                config: notes ? { notes } : {},
            }),
        });
        const data = await resp.json();
        if (!resp.ok) {
            const msg = extractErrorMessage(data, 'unknown error');
            showToast(`Scan blocked: ${msg}`, 'error');
            if (String(msg).includes('/api/targets')) {
                navigateTo('targets');
                prefillTargetRule(target);
            }
            return;
        }

        showToast(`Scan queued: ${data.scan_id.slice(0, 8)}`, 'success');
        navigateTo('active-scans');

        // Connect to scan WebSocket for live progress
        connectScanWs(data.scan_id, target);
    } catch (err) {
        showToast(`Failed to start scan: ${err.message}`, 'error');
    }
}

async function stopScan(scanId) {
    if (!confirm('Are you sure you want to stop this scan?')) return;
    try {
        const resp = await apiFetch(`/scans/${scanId}/stop`, { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Scan termination signal sent', 'success');
        } else {
            showToast(`Error stopping scan: ${extractErrorMessage(data, 'unknown error')}`, 'error');
        }
    } catch (err) {
        showToast(`Failed to stop scan: ${err.message}`, 'error');
    }
}

async function stopAllScans() {
    if (!confirm('Are you sure you want to stop ALL running scans?')) return;
    try {
        const resp = await apiFetch('/scans/stop-all', { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Termination signals sent to all scans', 'success');
        } else {
            showToast(`Error: ${extractErrorMessage(data, 'unknown error')}`, 'error');
        }
    } catch (err) {
        showToast(`Failed to stop all scans: ${err.message}`, 'error');
    }
}

// ══════════════════════════════════════
// Learning Page
// ══════════════════════════════════════

function safeJsonParse(value, fallback = null) {
    if (!value) return fallback;
    if (typeof value === 'object') return value;
    try { return JSON.parse(value); } catch (_) { return fallback; }
}

function fmtTs(ts) {
    const s = String(ts || '').trim();
    if (!s) return '-';
    // Expect ISO timestamps; keep them compact for tables.
    return s.replace('T', ' ').slice(0, 19);
}

function fmtMetrics(metrics) {
    const m = safeJsonParse(metrics, {});
    if (!m || typeof m !== 'object') return '-';
    const keys = ['fetched', 'extracted', 'skipped', 'errors', 'cards', 'source_items', 'categories', 'reason'];
    const parts = [];
    keys.forEach((k) => {
        if (m[k] === undefined || m[k] === null) return;
        parts.push(`${k}: ${m[k]}`);
    });
    return parts.length ? parts.join(' • ') : '-';
}

async function loadLearning() {
    try {
        const [crawlerStatusResp, learningStatusResp, memStatsResp, sourcesResp] = await Promise.all([
            apiFetch('/api/crawler/status', { cache: 'no-store' }),
            apiFetch('/api/learning/status', { cache: 'no-store' }),
            apiFetch('/api/memory/stats', { cache: 'no-store' }),
            apiFetch('/api/crawler/sources?limit=200', { cache: 'no-store' }),
        ]);

        const crawlerStatus = await crawlerStatusResp.json().catch(() => ({}));
        const learningStatus = await learningStatusResp.json().catch(() => ({}));
        const memStats = await memStatsResp.json().catch(() => ({}));
        const sourcesBundle = await sourcesResp.json().catch(() => ({}));

        if (!crawlerStatusResp.ok) throw new Error(extractErrorMessage(crawlerStatus, 'crawler status failed'));
        if (!learningStatusResp.ok) throw new Error(extractErrorMessage(learningStatus, 'learning status failed'));
        if (!memStatsResp.ok) throw new Error(extractErrorMessage(memStats, 'memory stats failed'));
        if (!sourcesResp.ok) throw new Error(extractErrorMessage(sourcesBundle, 'sources failed'));

        // Crawler status cards
        const crawlEnabledEl = document.getElementById('crawl-enabled');
        const crawlPendingEl = document.getElementById('crawl-pending');
        if (crawlEnabledEl) crawlEnabledEl.textContent = crawlerStatus.enabled ? 'Enabled' : 'Disabled';
        if (crawlPendingEl) crawlPendingEl.textContent = `Pending: ${crawlerStatus.pending_jobs ?? '-'}`;

        // Latest crawl run
        const crawlLatest = learningStatus.crawl || crawlerStatus.latest_run || null;
        const crawlStatusEl = document.getElementById('crawl-latest-status');
        const crawlMetricsEl = document.getElementById('crawl-latest-metrics');
        if (crawlStatusEl) crawlStatusEl.textContent = crawlLatest?.status ? String(crawlLatest.status) : '-';
        if (crawlMetricsEl) {
            const when = crawlLatest?.finished_at || crawlLatest?.started_at || '';
            const metrics = fmtMetrics(crawlLatest?.metrics);
            crawlMetricsEl.textContent = `${metrics}${when ? ` • ${fmtTs(when)}` : ''}`;
        }

        // Latest distill run
        const distillLatest = learningStatus.distill || null;
        const distillStatusEl = document.getElementById('distill-latest-status');
        const distillMetricsEl = document.getElementById('distill-latest-metrics');
        if (distillStatusEl) distillStatusEl.textContent = distillLatest?.status ? String(distillLatest.status) : '-';
        if (distillMetricsEl) {
            const when = distillLatest?.finished_at || distillLatest?.started_at || '';
            const metrics = fmtMetrics(distillLatest?.metrics);
            distillMetricsEl.textContent = `${metrics}${when ? ` • ${fmtTs(when)}` : ''}`;
        }

        // Memory stats
        const memCountEl = document.getElementById('memory-count');
        const memBreakdownEl = document.getElementById('memory-breakdown');
        if (memCountEl) memCountEl.textContent = String(memStats.total_items ?? '-');
        if (memBreakdownEl) {
            const byType = memStats.by_type || {};
            const parts = [];
            Object.keys(byType).sort().forEach((k) => parts.push(`${k}: ${byType[k]}`));
            memBreakdownEl.textContent = parts.length ? parts.join(' • ') : '-';
        }

        // Sources table
        const tbody = document.getElementById('learning-sources-tbody');
        if (tbody) {
            const rows = sourcesBundle.sources || [];
            tbody.innerHTML = '';
            rows.forEach((row) => {
                const tr = document.createElement('tr');
                const domain = String(row.domain || '').trim() || '-';
                const trust = row.trust_score !== undefined ? Number(row.trust_score).toFixed(2) : '-';
                const pages = row.pages_crawled !== undefined ? String(row.pages_crawled) : '-';
                const last = fmtTs(row.last_crawled_at);
                tr.innerHTML = `
                    <td>${escapeHtml(domain)}</td>
                    <td>${escapeHtml(trust)}</td>
                    <td>${escapeHtml(pages)}</td>
                    <td>${escapeHtml(last)}</td>
                `;
                tbody.appendChild(tr);
            });
            if (!rows.length) {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td colspan="4" style="color:var(--text-muted);padding:12px">No sources yet.</td>`;
                tbody.appendChild(tr);
            }
        }
    } catch (err) {
        showToast(`Learning load failed: ${err.message || err}`, 'error');
    }
}

// ══════════════════════════════════════
// Swarm Runs
// ══════════════════════════════════════

async function startSwarmRun() {
    const target = (document.getElementById('swarm-target')?.value || '').trim();
    const objective = (document.getElementById('swarm-objective')?.value || '').trim();
    const methodology = (document.getElementById('swarm-methodology')?.value || 'owasp').trim().toLowerCase();
    const scanType = (document.getElementById('swarm-scan-type')?.value || 'quick').trim().toLowerCase();

    if (!target) {
        showToast('Swarm target is required.', 'error');
        return;
    }
    if (!objective) {
        showToast('Swarm objective is required.', 'error');
        return;
    }

    try {
        const resp = await apiFetch('/api/swarm/runs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target,
                objective,
                methodology,
                scan_type: scanType === 'full' ? 'full' : 'quick',
                config: {},
            }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Failed to queue swarm run: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast(`Swarm queued: ${String(data.run_id || '').slice(0, 8)}`, 'success');
        await loadSwarmRuns();
        if (data.run_id) connectSwarmWs(data.run_id);
    } catch (err) {
        showToast(`Swarm queue failed: ${err.message || err}`, 'error');
    }
}

async function stopSwarmRun(runId) {
    if (!runId) return;
    if (!confirm(`Stop swarm run ${runId.slice(0, 8)}?`)) return;
    try {
        const resp = await apiFetch(`/api/swarm/runs/${encodeURIComponent(runId)}/stop`, { method: 'POST' });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Stop failed: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast(`Swarm stopping: ${runId.slice(0, 8)}`, 'info');
        await loadSwarmRuns();
    } catch (err) {
        showToast(`Stop failed: ${err.message || err}`, 'error');
    }
}

function _swarmStatusBadge(status) {
    const s = String(status || '').toLowerCase();
    if (s === 'completed') return '<span class="badge badge-completed">Completed</span>';
    if (s === 'error') return '<span class="badge badge-error">Error</span>';
    if (s === 'stopping') return '<span class="badge badge-warning">Stopping</span>';
    if (s === 'running') return '<span class="badge badge-running">Running</span>';
    return '<span class="badge badge-info">Queued</span>';
}

async function loadSwarmRuns() {
    const tbody = document.getElementById('swarm-runs-tbody');
    if (!tbody) return;
    try {
        const resp = await apiFetch('/api/swarm/runs?limit=100', { cache: 'no-store' });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(extractErrorMessage(data, 'load failed'));

        const runs = Array.isArray(data.runs) ? data.runs : [];
        tbody.innerHTML = '';
        if (!runs.length) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td colspan="7" style="color:var(--text-muted);padding:12px">No swarm runs yet.</td>`;
            tbody.appendChild(tr);
            return;
        }
        runs.forEach((run) => {
            const runId = String(run.run_id || '');
            const status = String(run.status || 'queued');
            const tr = document.createElement('tr');
            tr.id = `swarm-row-${runId}`;
            tr.innerHTML = `
                <td><code>${escapeHtml(runId.slice(0, 8))}</code></td>
                <td>${escapeHtml(run.target || '-')}</td>
                <td>${escapeHtml(run.methodology || '-')}</td>
                <td>${escapeHtml(run.scan_type || '-')}</td>
                <td class="swarm-status">${_swarmStatusBadge(status)}</td>
                <td>${escapeHtml(fmtTs(run.created_at || ''))}</td>
                <td>
                    <div style="display:flex;gap:8px;align-items:center">
                        <button class="btn btn-sm btn-secondary" onclick="connectSwarmWs('${runId}')">Watch</button>
                        <button class="btn btn-sm btn-secondary" onclick="stopSwarmRun('${runId}')">Stop</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
            if (status === 'running' || status === 'queued' || status === 'stopping') {
                connectSwarmWs(runId);
            }
        });
    } catch (err) {
        showToast(`Swarm load failed: ${err.message || err}`, 'error');
    }
}

function connectSwarmWs(runId) {
    if (!runId) return;
    if (activeSwarmWs[runId] && activeSwarmWs[runId].readyState === WebSocket.OPEN) return;
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const query = wsAuthQuery();
    const suffix = query ? `?${query}` : '';
    const ws = new WebSocket(`${protocol}://${location.host}/ws/swarm/${encodeURIComponent(runId)}${suffix}`);
    activeSwarmWs[runId] = ws;

    ws.onmessage = async (event) => {
        const data = JSON.parse(event.data || '{}');
        if (!data || !data.type) return;
        const row = document.getElementById(`swarm-row-${runId}`);
        const statusCell = row ? row.querySelector('.swarm-status') : null;
        if (!statusCell) return;

        if (data.type === 'status' && data.run) {
            statusCell.innerHTML = _swarmStatusBadge(data.run.status);
            return;
        }
        if (data.type === 'run_started') statusCell.innerHTML = _swarmStatusBadge('running');
        if (data.type === 'run_completed') statusCell.innerHTML = _swarmStatusBadge('completed');
        if (data.type === 'run_error') statusCell.innerHTML = _swarmStatusBadge('error');
        if (data.type === 'stopping' || data.type === 'run_stopped') statusCell.innerHTML = _swarmStatusBadge('stopping');
    };

    ws.onclose = () => {
        delete activeSwarmWs[runId];
    };
}

async function runLearnSeed() {
    const input = document.getElementById('learn-seed-url');
    let raw = (input?.value || '').trim();
    if (!raw) {
        showToast('Seed URL is required.', 'error');
        return;
    }
    if (!raw.includes('://')) raw = `https://${raw}`;
    let url;
    try {
        url = new URL(raw);
    } catch (_) {
        showToast('Invalid Seed URL.', 'error');
        return;
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
        showToast('Seed URL must be http(s).', 'error');
        return;
    }

    const asNumOrNull = (id) => {
        const raw = (document.getElementById(id)?.value || '').trim();
        if (!raw) return null;
        const n = Number(raw);
        return Number.isFinite(n) ? n : null;
    };
    const allowSub = document.getElementById('learn-allow-subdomains')?.checked;

    try {
        const resp = await apiFetch('/api/crawler/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                seeds: [url.toString()],
                focused: true,
                distill_after: true,
                max_depth: asNumOrNull('learn-max-depth'),
                max_pages_per_domain: asNumOrNull('learn-max-pages-domain'),
                max_pages_per_day: asNumOrNull('learn-max-pages-day'),
                allow_subdomains: allowSub === undefined ? null : Boolean(allowSub),
            }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Learn failed: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast(`Learning queued: ${String(data.job_id || '').slice(0, 8)}`, 'success');
        loadLearning();
    } catch (err) {
        showToast(`Learn failed: ${err.message || err}`, 'error');
    }
}

async function triggerDistillNow() {
    try {
        const resp = await apiFetch('/api/learning/distill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ limit: 350 }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Distill failed: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast(`Distill queued: ${String(data.job_id || '').slice(0, 8)}`, 'success');
        loadLearning();
    } catch (err) {
        showToast(`Distill failed: ${err.message || err}`, 'error');
    }
}

async function loadCrawlerPolicyUI() {
    const domain = (document.getElementById('crawler-policy-domain')?.value || '*').trim() || '*';
    const statusEl = document.getElementById('crawler-policy-status');
    if (statusEl) statusEl.textContent = 'Loading...';
    try {
        const resp = await apiFetch(`/api/crawler/policy?domain=${encodeURIComponent(domain)}`, { cache: 'no-store' });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(extractErrorMessage(data, 'policy load failed'));
        const policy = data.policy || null;
        if (!policy) {
            if (statusEl) statusEl.textContent = `No policy found for ${domain}.`;
            return;
        }
        const allowEl = document.getElementById('crawler-policy-allow');
        const mdEl = document.getElementById('crawler-policy-max-depth');
        const capEl = document.getElementById('crawler-policy-daily-cap');
        const tfEl = document.getElementById('crawler-policy-trust-floor');
        if (allowEl) allowEl.value = policy.allow ? 'true' : 'false';
        if (mdEl) mdEl.value = policy.max_depth === null || policy.max_depth === undefined ? '' : String(policy.max_depth);
        if (capEl) capEl.value = policy.daily_cap === null || policy.daily_cap === undefined ? '' : String(policy.daily_cap);
        if (tfEl) tfEl.value = policy.trust_floor === null || policy.trust_floor === undefined ? '' : String(policy.trust_floor);
        if (statusEl) statusEl.textContent = `Loaded policy for ${domain} (updated: ${fmtTs(policy.updated_at)}).`;
    } catch (err) {
        if (statusEl) statusEl.textContent = `Load failed: ${err.message || err}`;
        showToast(`Policy load failed: ${err.message || err}`, 'error');
    }
}

async function saveCrawlerPolicyUI() {
    const domain = (document.getElementById('crawler-policy-domain')?.value || '*').trim() || '*';
    const allowRaw = (document.getElementById('crawler-policy-allow')?.value || 'true').trim().toLowerCase();
    const maxDepthRaw = (document.getElementById('crawler-policy-max-depth')?.value || '').trim();
    const capRaw = (document.getElementById('crawler-policy-daily-cap')?.value || '').trim();
    const trustRaw = (document.getElementById('crawler-policy-trust-floor')?.value || '').trim();
    const statusEl = document.getElementById('crawler-policy-status');

    const asNumOrNull = (raw) => {
        if (!raw) return null;
        const n = Number(raw);
        return Number.isFinite(n) ? n : null;
    };

    const payload = {
        domain,
        allow: allowRaw === 'true',
        max_depth: asNumOrNull(maxDepthRaw),
        daily_cap: asNumOrNull(capRaw),
        trust_floor: asNumOrNull(trustRaw),
    };

    if (statusEl) statusEl.textContent = 'Saving...';
    try {
        const resp = await apiFetch('/api/crawler/policy', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(extractErrorMessage(data, 'policy save failed'));
        if (statusEl) statusEl.textContent = `Saved policy for ${domain}.`;
        showToast('Crawler policy saved.', 'success');
        loadLearning();
    } catch (err) {
        if (statusEl) statusEl.textContent = `Save failed: ${err.message || err}`;
        showToast(`Policy save failed: ${err.message || err}`, 'error');
    }
}

function parseHostnameFromTarget(raw) {
    const input = (raw || '').trim();
    if (!input) return '';
    try {
        const withScheme = input.includes('://') ? input : `http://${input}`;
        const u = new URL(withScheme);
        return (u.hostname || '').toLowerCase().replace(/\.$/, '');
    } catch (_) {
        // fallback: take until slash/space, strip port.
        const hostish = input.split(/[\/\s]/, 1)[0];
        return hostish.split(':', 1)[0].toLowerCase().replace(/\.$/, '');
    }
}

function scheduleAllowlistCheck(rawTarget) {
    const target = (rawTarget || '').trim();
    lastAllowlistTarget = target;
    if (allowlistCheckTimer) clearTimeout(allowlistCheckTimer);
    allowlistCheckTimer = setTimeout(() => {
        checkAllowlist(target).catch(() => {});
    }, 350);
}

async function checkAllowlist(target) {
    const row = document.getElementById('allowlist-row');
    const badge = document.getElementById('allowlist-badge');
    const norm = document.getElementById('allowlist-normalized');
    const addBtn = document.getElementById('allowlist-add-btn');
    if (row && badge && norm && addBtn) {
        if (!target) {
            row.style.display = 'none';
            addBtn.style.display = 'none';
            badge.textContent = 'Checking...';
            badge.style.background = '';
            badge.style.color = '';
            norm.textContent = '';
            return null;
        }
        row.style.display = 'flex';
        badge.textContent = 'Checking...';
        badge.style.background = 'rgba(234,179,8,0.10)';
        badge.style.color = 'var(--yellow)';
        addBtn.style.display = 'none';
        norm.textContent = '';
    }

    // Avoid spamming if user is typing.
    if (!target) return null;

    try {
        const resp = await apiFetch(`/api/targets/check?target=${encodeURIComponent(target)}`);
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) return null;

        // Only update UI if this is still the latest target.
        if (target !== lastAllowlistTarget) return data;

        if (row && badge && norm && addBtn) {
            norm.textContent = data.normalized ? `normalized: ${data.normalized}` : '';
            if (data.allowed) {
                badge.textContent = 'Allowlisted';
                badge.style.background = 'rgba(34,197,94,0.10)';
                badge.style.color = 'var(--green)';
                addBtn.style.display = 'none';
            } else {
                badge.textContent = 'Blocked';
                badge.style.background = 'rgba(239,68,68,0.10)';
                badge.style.color = 'var(--red)';
                addBtn.style.display = 'inline-flex';
            }
        }
        return data;
    } catch (_) {
        return null;
    }
}

function prefillTargetRule(target) {
    const pattern = document.getElementById('target-rule-pattern');
    const type = document.getElementById('target-rule-type');
    if (pattern) pattern.value = parseHostnameFromTarget(target) || (target || '').trim();
    if (type) type.value = 'domain';
}

async function addTargetAllowlistFromUI() {
    const raw = (document.getElementById('scan-target')?.value || '').trim();
    const host = parseHostnameFromTarget(raw);
    if (!host) {
        showToast('Invalid target.', 'error');
        return;
    }
    try {
        const resp = await apiFetch('/api/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'domain', pattern: host, created_by: 'ui', enabled: true }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Failed to add allowlist: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast(`Allowlisted: ${host}`, 'success');
        await loadTargets(false);
        await checkAllowlist(raw);
    } catch (err) {
        showToast(`Failed to add allowlist: ${err.message}`, 'error');
    }
}

function connectScanWs(scanId, target) {
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const query = wsAuthQuery();
    const suffix = query ? `?${query}` : '';
    const ws = new WebSocket(`${protocol}://${location.host}/ws/scan/${scanId}${suffix}`);

    const container = document.getElementById('active-scans-list');

    // Create scan card
    const scanCard = document.createElement('div');
    scanCard.className = 'card';
    scanCard.id = `scan-card-${scanId}`;
    scanCard.innerHTML = `
        <div class="card-header">
            <div style="display:flex;justify-content:space-between;align-items:center;width:100%">
                <span>🔍 Scanning: ${escapeHtml(target)}</span>
                <div style="display:flex;gap:8px;align-items:center">
                    <span class="badge badge-running">Running</span>
                    <button class="btn btn-sm btn-secondary" style="background:#ff475722;color:#ff4757;border-color:#ff475744" onclick="stopScan('${scanId}')">Stop</button>
                </div>
            </div>
        </div>
        <div class="card-body">
            <div style="margin-bottom:12px">
                <div style="display:flex;justify-content:space-between;margin-bottom:6px">
                    <span id="scan-status-${scanId}" style="font-size:13px">Initializing...</span>
                    <span id="scan-progress-${scanId}" style="font-size:13px;color:var(--accent)">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-bar-fill" id="scan-bar-${scanId}" style="width:0%"></div>
                </div>
            </div>
            <div class="terminal" id="scan-terminal-${scanId}" style="max-height:300px"></div>
            <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end" id="scan-actions-${scanId}"></div>
        </div>
    `;

    // Remove empty state or prepend
    const empty = container.querySelector('.empty-state');
    if (empty) container.innerHTML = '';
    container.prepend(scanCard);

    const terminal = document.getElementById(`scan-terminal-${scanId}`);

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleScanEvent(scanId, data, terminal);
    };

    ws.onclose = (evt) => {
        if (suppressWsReconnect) {
            delete activeScanWs[scanId];
            return;
        }
        if (evt && (evt.code === 4401 || evt.code === 4403)) {
            showToast('Scan WebSocket auth failed.', 'error');
        }
        delete activeScanWs[scanId];
    };

    activeScanWs[scanId] = ws;
}

function handleScanEvent(scanId, data, terminal) {
    const statusEl = document.getElementById(`scan-status-${scanId}`);
    const progressEl = document.getElementById(`scan-progress-${scanId}`);
    const barEl = document.getElementById(`scan-bar-${scanId}`);

    switch (data.type) {
        case 'status':
            if (statusEl) statusEl.textContent = data.message || 'Processing...';
            if (data.progress !== undefined) {
                if (progressEl) progressEl.textContent = `${data.progress}%`;
                if (barEl) barEl.style.width = `${data.progress}%`;
            }
            break;

        case 'phase_start':
            appendTerminalLine(terminal, `\n═══ Phase: ${data.phase} ═══`, 'line-info');
            if (statusEl) statusEl.textContent = `Phase: ${data.phase}`;
            break;

        case 'phase_complete':
            appendTerminalLine(terminal, `✓ Phase complete: ${data.phase}`, 'line-success');
            break;

        case 'tool_start':
            appendTerminalLine(terminal, `\n▶ Running: ${data.tool}`, 'line-tool');
            appendTerminalLine(terminal, `$ ${data.command}`, 'line-tool');
            if (statusEl) statusEl.textContent = `Running: ${data.tool} — ${data.description || ''}`;
            if (data.progress !== undefined) {
                if (progressEl) progressEl.textContent = `${data.progress}%`;
                if (barEl) barEl.style.width = `${data.progress}%`;
            }
            break;

        case 'tool_output':
            appendTerminalLine(terminal, data.line, 'line-output');
            break;

        case 'tool_complete':
            const sym = data.return_code === 0 ? '✓' : '✗';
            const cls = data.return_code === 0 ? 'line-success' : 'line-error';
            appendTerminalLine(terminal, `${sym} ${data.tool} completed (${data.duration}s) [${data.severity}]`, cls);
            if (data.progress !== undefined) {
                if (progressEl) progressEl.textContent = `${data.progress}%`;
                if (barEl) barEl.style.width = `${data.progress}%`;
            }
            break;

        case 'ai_plan':
            appendTerminalLine(terminal, `\n🤖 AI Strategy (${data.model}):`, 'line-info');
            const planLines = (data.plan || '').split('\n').slice(0, 20);
            planLines.forEach(l => appendTerminalLine(terminal, l, 'line-output'));
            break;

        case 'ai_summary':
            appendTerminalLine(terminal, `\n🤖 AI Analysis Summary:`, 'line-info');
            const summaryLines = (data.summary || '').split('\n').slice(0, 30);
            summaryLines.forEach(l => appendTerminalLine(terminal, l, 'line-output'));
            break;

        case 'swarm_summary':
            appendTerminalLine(terminal, `\n🧠 Swarm Synthesis:`, 'line-info');
            const swarmLines = (data.summary || '').split('\n').slice(0, 20);
            swarmLines.forEach(l => appendTerminalLine(terminal, l, 'line-output'));
            break;

        case 'complete':
            if (statusEl) statusEl.textContent = '✅ Scan Completed';
            if (progressEl) progressEl.textContent = '100%';
            if (barEl) barEl.style.width = '100%';
            appendTerminalLine(terminal, `\n✅ ${data.message}`, 'line-success');

            const badge = document.querySelector(`#scan-card-${scanId} .badge`);
            if (badge) { badge.className = 'badge badge-completed'; badge.textContent = 'Completed'; }

            const actionsEl = document.getElementById(`scan-actions-${scanId}`);
            if (actionsEl) {
                actionsEl.innerHTML = `
                    <button class="btn btn-sm btn-secondary" onclick="generateReport('${scanId}','json')">📋 JSON</button>
                    <button class="btn btn-sm btn-secondary" onclick="generateReport('${scanId}','html')">🌐 HTML</button>
                    <button class="btn btn-sm btn-primary" onclick="generateReport('${scanId}','pdf')">📄 PDF</button>
                `;
            }

            showToast('Scan completed successfully!', 'success');
            break;

        case 'stopped':
            if (statusEl) statusEl.textContent = '🛑 Scan Stopped';
            appendTerminalLine(terminal, `\n🛑 ${data.message || 'Scan stopped by user'}`, 'line-error');

            const stopBadge = document.querySelector(`#scan-card-${scanId} .badge`);
            if (stopBadge) { stopBadge.className = 'badge badge-error'; stopBadge.textContent = 'Stopped'; }

            const stopActionsEl = document.getElementById(`scan-actions-${scanId}`);
            if (stopActionsEl) {
                stopActionsEl.innerHTML = `
                    <button class="btn btn-sm btn-secondary" onclick="viewScanDetails('${scanId}')">View Results</button>
                `;
            }

            // Remove stop button from header if it exists
            const headerBtn = document.querySelector(`#scan-card-${scanId} .card-header button`);
            if (headerBtn) headerBtn.remove();

            showToast('Scan stopped.', 'info');
            break;

        case 'error':
            if (statusEl) statusEl.textContent = `❌ Error: ${data.message}`;
            appendTerminalLine(terminal, `❌ Error: ${data.message}`, 'line-error');
            const errBadge = document.querySelector(`#scan-card-${scanId} .badge`);
            if (errBadge) { errBadge.className = 'badge badge-error'; errBadge.textContent = 'Error'; }
            showToast(`Scan error: ${data.message}`, 'error');
            break;
    }
}

function appendTerminalLine(terminal, text, className) {
    if (!terminal) return;
    const line = document.createElement('div');
    line.className = className || '';
    line.textContent = text;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}


// ══════════════════════════════════════
// Reports
// ══════════════════════════════════════

async function generateReport(scanId, format) {
    try {
        showToast(`Generating ${format.toUpperCase()} report...`, 'info');
        const resp = await apiFetch(`/api/reports/${scanId}?format=${format}`, { method: 'POST' });
        const data = await resp.json();

        if (data.report_id) {
            await downloadReport(data.report_id);
            showToast(`${format.toUpperCase()} report generated!`, 'success');
        }
    } catch (err) {
        showToast(`Report generation failed: ${err.message}`, 'error');
    }
}

async function downloadReport(reportId) {
    try {
        const resp = await apiFetch(`/api/reports/download/${reportId}`);
        const blob = await resp.blob();
        const dispo = resp.headers.get('Content-Disposition') || '';
        let filename = `report_${reportId}`;
        const m = dispo.match(/filename\\*?=(?:UTF-8''|\"?)([^\";]+)/i);
        if (m && m[1]) filename = decodeURIComponent(m[1].replace(/^\"|\"$/g, ''));

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
        showToast(`Download failed: ${err.message}`, 'error');
    }
}

async function loadReports() {
    try {
        const resp = await apiFetch('/api/reports');
        const data = await resp.json();
        const container = document.getElementById('reports-list');

        if (!data.reports || data.reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="icon">📄</div><h3>No Reports</h3><p>Complete a scan and generate reports.</p></div>';
            return;
        }

        container.innerHTML = data.reports.map(r => `
            <div class="card" style="margin-bottom:10px">
                <div class="card-body" style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px">
                    <div>
                        <strong>${r.filename}</strong>
                        <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Scan: ${r.scan_id.slice(0, 8)} • ${r.created_at}</div>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center">
                        <span class="badge badge-info">${r.format.toUpperCase()}</span>
                        <button class="btn btn-sm btn-primary" onclick="downloadReport('${r.id}')">Download</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load reports:', err);
    }
}


// ══════════════════════════════════════
// Dashboard & History
// ══════════════════════════════════════

async function loadDashboard() {
    try {
        const resp = await apiFetch('/scans?limit=10');
        const data = await resp.json();
        const scans = data.scans || [];

        document.getElementById('stat-total-scans').textContent = scans.length;
        document.getElementById('stat-active-scans').textContent =
            scans.filter(s => s.status === 'running').length;

        // Populate tools/models counts from summary endpoint.
        try {
            const sresp = await apiFetch('/api/frameworks/summary');
            const sdata = await sresp.json();
            const toolsTotal = Number(sdata?.tools?.total || 0);
            const models = sdata?.ai_models?.available || [];
            const statTools = document.getElementById('stat-tools');
            const statModels = document.getElementById('stat-models');
            if (statTools && toolsTotal) statTools.textContent = String(toolsTotal);
            if (statModels) statModels.textContent = String(models.length || '-');
        } catch (_) {
            // non-fatal
        }

        const activity = document.getElementById('recent-activity');
        if (scans.length > 0) {
            activity.innerHTML = scans.slice(0, 5).map(s => `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid rgba(30,45,74,0.3)">
                    <div>
                        <div style="font-size:13px;font-weight:500">${escapeHtml(s.target)}</div>
                        <div style="font-size:11px;color:var(--text-muted)">${s.methodology.toUpperCase()} • ${s.created_at?.slice(0, 16) || ''}</div>
                    </div>
                    <span class="badge badge-${s.status}">${s.status}</span>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

async function loadHistory() {
    try {
        const resp = await apiFetch('/scans?limit=50');
        const data = await resp.json();
        const tbody = document.getElementById('history-tbody');

        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No scan history</td></tr>';
            return;
        }

        tbody.innerHTML = data.scans.map(s => `
            <tr>
                <td style="font-family:var(--mono);font-size:12px">${s.id.slice(0, 8)}</td>
                <td>${escapeHtml(s.target)}</td>
                <td><span class="badge badge-info">${s.methodology.toUpperCase()}</span></td>
                <td><span class="badge badge-${s.status}">${s.status}</span></td>
                <td>
                    <div class="progress-bar" style="width:100px;height:4px">
                        <div class="progress-bar-fill" style="width:${Math.max(0, s.progress || 0)}%"></div>
                    </div>
                </td>
                <td style="font-size:12px;color:var(--text-muted)">${s.created_at?.slice(0, 16) || ''}</td>
                <td>
                    <div style="display:flex;gap:4px">
                        ${s.status === 'completed' ? `
                            <button class="btn btn-sm btn-secondary" onclick="generateReport('${s.id}','html')">Report</button>
                        ` : s.status === 'running' ? `
                            <button class="btn btn-sm btn-secondary" style="color:var(--red)" onclick="stopScan('${s.id}')">Stop</button>
                        ` : ''}
                        <button class="btn btn-sm btn-secondary" onclick="viewScanDetails('${s.id}')">View</button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

async function loadActiveScans() {
    try {
        const resp = await apiFetch('/scans?limit=20');
        const data = await resp.json();
        const active = (data.scans || []).filter(s => s.status === 'running');
        const container = document.getElementById('active-scans-list');

        // Auto-connect WS for running scans even after reload/navigation.
        for (const s of active) {
            if (!activeScanWs[s.id]) {
                connectScanWs(s.id, s.target);
            }
        }

        if (active.length === 0 && Object.keys(activeScanWs).length === 0) {
            // Only show empty if no WS connections either
            if (!container.querySelector('.card')) {
                container.innerHTML = '<div class="empty-state"><div class="icon">⚡</div><h3>No Active Scans</h3><p>Launch a new scan to see live progress here.</p></div>';
            }
        }
    } catch (err) {
        console.error('Failed to load active scans:', err);
    }
}

async function viewScanDetails(scanId) {
    try {
        const resp = await apiFetch(`/scans/${scanId}`);
        const data = await resp.json();

        navigateTo('active-scans');
        const container = document.getElementById('active-scans-list');

        const results = data.results || [];
        const resultsHtml = results.map(r => `
            <div style="margin-bottom:12px;padding:12px;background:var(--bg-primary);border-radius:var(--radius-sm);border:1px solid var(--border)">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                    <strong style="color:var(--accent)">${r.tool_name}</strong>
                    <span class="badge badge-${r.severity}">${r.severity}</span>
                </div>
                <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px">Phase: ${r.phase} | <code>${r.command}</code></div>
                ${r.output ? `<pre style="background:var(--bg-secondary);padding:10px;border-radius:4px;font-size:11px;max-height:200px;overflow:auto">${escapeHtml(r.output.slice(0, 3000))}</pre>` : ''}
            </div>
        `).join('');

        container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    📋 Scan: ${data.target}
                    <div style="display:flex;gap:8px;align-items:center">
                        <span class="badge badge-${data.status}">${data.status}</span>
                        ${data.status === 'running' ? `<button class="btn btn-sm btn-secondary" style="background:#ff475722;color:#ff4757;border-color:#ff475744" onclick="stopScan('${scanId}')">Stop</button>` : ''}
                        <button class="btn btn-sm btn-secondary" onclick="loadActiveScans()">← Back</button>
                    </div>
                </div>
                <div class="card-body">
                    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
                        <div style="padding:12px;background:var(--bg-tertiary);border-radius:6px"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase">Methodology</div><div style="font-size:15px;font-weight:600;margin-top:4px">${data.methodology?.toUpperCase()}</div></div>
                        <div style="padding:12px;background:var(--bg-tertiary);border-radius:6px"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase">Results</div><div style="font-size:15px;font-weight:600;margin-top:4px">${results.length} findings</div></div>
                        <div style="padding:12px;background:var(--bg-tertiary);border-radius:6px"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase">Progress</div><div style="font-size:15px;font-weight:600;margin-top:4px">${data.progress || 0}%</div></div>
                    </div>
                    ${data.status === 'completed' ? `
                        <div style="margin-bottom:16px;display:flex;gap:8px">
                            <button class="btn btn-sm btn-secondary" onclick="generateReport('${scanId}','json')">📋 JSON Report</button>
                            <button class="btn btn-sm btn-secondary" onclick="generateReport('${scanId}','html')">🌐 HTML Report</button>
                            <button class="btn btn-sm btn-primary" onclick="generateReport('${scanId}','pdf')">📄 PDF Report</button>
                        </div>
                    ` : ''}
                    ${resultsHtml || '<div style="color:var(--text-muted);padding:20px;text-align:center">No results yet</div>'}
                </div>
            </div>
        `;
    } catch (err) {
        showToast(`Failed to load scan details: ${err.message}`, 'error');
    }
}


// ══════════════════════════════════════
// Frameworks
// ══════════════════════════════════════

async function showFrameworkTab(tab, evt = null) {
    document.querySelectorAll('.framework-tab').forEach(t => t.classList.remove('active'));
    if (evt && evt.target && evt.target.classList) {
        evt.target.classList.add('active');
    } else {
        const nth = tab === 'owasp' ? 1 : tab === 'attack' ? 2 : 3;
        document.querySelector(`.framework-tab:nth-child(${nth})`)?.classList.add('active');
    }

    const content = document.getElementById('framework-content');
    content.innerHTML = '<div style="padding:40px;text-align:center"><div class="spinner"></div></div>';

    try {
        const endpoints = { owasp: '/api/frameworks/owasp', attack: '/api/frameworks/attack', killchain: '/api/frameworks/killchain' };
        const resp = await apiFetch(endpoints[tab]);
        const data = await resp.json();

        if (tab === 'owasp') {
            content.innerHTML = `<div class="framework-list">${(data.categories || []).map(c => `
                <div class="framework-item" onclick="showOwaspCategory('${c.id}')">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <div>
                            <div class="fi-id">${c.id}</div>
                            <div class="fi-title">${c.name}</div>
                            <div class="fi-desc">${c.description}</div>
                        </div>
                        <span class="badge badge-info">${c.test_count} tests</span>
                    </div>
                </div>
            `).join('')}</div>`;
        } else if (tab === 'attack') {
            content.innerHTML = `<div class="framework-list">${(data.tactics || []).map(t => `
                <div class="framework-item">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <div>
                            <div class="fi-id">${t.id}</div>
                            <div class="fi-title">${t.name}</div>
                            <div class="fi-desc">${t.description}</div>
                        </div>
                        <span class="badge badge-info">${t.technique_count} techniques</span>
                    </div>
                </div>
            `).join('')}</div>`;
        } else {
            content.innerHTML = `<div class="framework-list">${(data.phases || []).map(p => `
                <div class="framework-item">
                    <div>
                        <div class="fi-id">Phase ${p.phase}</div>
                        <div class="fi-title">${p.name}</div>
                        <div class="fi-desc">${p.description}</div>
                    </div>
                </div>
            `).join('')}</div>`;
        }
    } catch (err) {
        content.innerHTML = `<div class="empty-state"><h3>Failed to load</h3><p>${err.message}</p></div>`;
    }
}

async function showOwaspCategory(catId) {
    const content = document.getElementById('framework-content');
    try {
        const resp = await apiFetch(`/api/frameworks/owasp/${catId}`);
        const data = await resp.json();

        content.innerHTML = `
            <button class="btn btn-sm btn-secondary" onclick="showFrameworkTab('owasp')" style="margin-bottom:16px">← Back to Categories</button>
            <h3 style="margin-bottom:4px">${data.name}</h3>
            <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px">${data.description}</p>
            <div class="framework-list">
                ${(data.test_cases || []).map(tc => `
                    <div class="framework-item">
                        <div class="fi-id">${tc.id}</div>
                        <div class="fi-title">${tc.name}</div>
                        <div class="fi-desc">${tc.description}</div>
                        <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
                            ${(tc.tools || []).map(t => `<span class="badge badge-info">${t}</span>`).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (err) {
        showToast(`Failed to load category: ${err.message}`, 'error');
    }
}

async function loadFrameworksSummary() {
    try {
        const resp = await apiFetch('/api/frameworks/summary');
        const data = await resp.json();
        showToast(`Frameworks: ${data.frameworks.map(f => f.name).join(', ')} | ${data.tools.total} tools`, 'info');
    } catch (err) {
        console.error('Frameworks summary error:', err);
    }
}


// ══════════════════════════════════════
// Targets (Allowlist)
// ══════════════════════════════════════

async function loadTargets(showToastOnError = true) {
    const container = document.getElementById('targets-list');
    if (!container) return;
    try {
        const resp = await apiFetch('/api/targets');
        const data = await resp.json();
        if (!resp.ok) {
            if (showToastOnError) showToast(`Failed to load targets: ${extractErrorMessage(data)}`, 'error');
            return;
        }
        const rules = data.rules || [];
        if (rules.length === 0) {
            container.innerHTML = '<div class="empty-state" style="padding:26px"><div class="icon">🎯</div><h3>No allowlist rules</h3><p>Add a rule to enable scanning. Example: <code>scanme.nmap.org</code></p></div>';
            return;
        }
        container.innerHTML = `
            <div class="card" style="background:transparent;border:none;box-shadow:none;margin:0">
                <div class="card-body" style="padding:0;overflow-x:auto">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Pattern</th>
                                <th>Enabled</th>
                                <th>Created</th>
                                <th>By</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                        ${rules.map(r => `
                            <tr>
                                <td><span class="badge badge-info">${escapeHtml(String(r.type || ''))}</span></td>
                                <td style="font-family:var(--mono);font-size:12px">${escapeHtml(String(r.pattern || ''))}</td>
                                <td>${Number(r.enabled || 0) === 1 ? '<span class="badge badge-completed">yes</span>' : '<span class="badge badge-error">no</span>'}</td>
                                <td style="font-size:12px;color:var(--text-muted)">${escapeHtml(String(r.created_at || '').slice(0, 16))}</td>
                                <td style="font-size:12px;color:var(--text-muted)">${escapeHtml(String(r.created_by || ''))}</td>
                                <td style="text-align:right">
                                    <button class="btn btn-sm btn-secondary" style="color:var(--red)" onclick="deleteTargetRule('${r.id}')">Delete</button>
                                </td>
                            </tr>
                        `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    } catch (err) {
        if (showToastOnError) showToast(`Failed to load targets: ${err.message}`, 'error');
    }
}

async function createTargetRule() {
    const type = (document.getElementById('target-rule-type')?.value || 'domain').trim();
    const patternRaw = (document.getElementById('target-rule-pattern')?.value || '').trim();
    const pattern = type === 'domain' ? (parseHostnameFromTarget(patternRaw) || patternRaw) : patternRaw;
    if (!pattern) {
        showToast('Pattern is required.', 'error');
        return;
    }
    try {
        const resp = await apiFetch('/api/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, pattern, created_by: 'ui', enabled: true }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Failed to add: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        document.getElementById('target-rule-pattern').value = '';
        showToast('Allowlist rule added.', 'success');
        await loadTargets(false);
        // Update scan page badge if it matches.
        const scanTarget = (document.getElementById('scan-target')?.value || '').trim();
        if (scanTarget) scheduleAllowlistCheck(scanTarget);
    } catch (err) {
        showToast(`Failed to add: ${err.message}`, 'error');
    }
}

async function deleteTargetRule(ruleId) {
    if (!ruleId) return;
    if (!confirm('Delete this allowlist rule?')) return;
    try {
        const resp = await apiFetch(`/api/targets/${ruleId}`, { method: 'DELETE' });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            showToast(`Delete failed: ${extractErrorMessage(data, 'unknown error')}`, 'error');
            return;
        }
        showToast('Rule deleted.', 'success');
        await loadTargets(false);
        const scanTarget = (document.getElementById('scan-target')?.value || '').trim();
        if (scanTarget) scheduleAllowlistCheck(scanTarget);
    } catch (err) {
        showToast(`Delete failed: ${err.message}`, 'error');
    }
}


// ══════════════════════════════════════
// Tools Catalog
// ══════════════════════════════════════

async function loadToolsCatalog() {
    try {
        const resp = await apiFetch('/api/tools?limit=120&offset=0');
        const data = await resp.json();
        toolsData = data.tools || [];
        toolsTotal = Number(data.total || toolsData.length || 0);
        renderTools(toolsData);
        const meta = document.getElementById('tools-meta');
        if (meta) {
            meta.textContent = toolsTotal > toolsData.length
                ? `Loaded ${toolsData.length} of ${toolsTotal} tools. Use search to query the full catalog.`
                : `Loaded ${toolsData.length} tools.`;
        }
    } catch (err) {
        console.error('Failed to load tools:', err);
    }
}

function renderTools(tools) {
    const grid = document.getElementById('tools-grid');
    if (!grid) return;

    grid.innerHTML = tools.map(t => {
        const riskColor = { low: 'var(--green)', medium: 'var(--yellow)', high: 'var(--orange)', critical: 'var(--red)' };
        return `
            <div class="tool-card">
                <div class="tool-name">${t.name}</div>
                <div class="tool-cat">${t.category.replace(/_/g, ' ')}</div>
                <div class="tool-desc">${t.description}</div>
                <div class="tool-risk">
                    <span class="badge" style="background:${riskColor[t.risk_level]}22;color:${riskColor[t.risk_level]}">${t.risk_level} risk</span>
                </div>
            </div>
        `;
    }).join('');
}

function searchToolsUI() {
    const q = document.getElementById('tool-search').value.toLowerCase().trim();
    if (!q) {
        renderTools(toolsData);
        const meta = document.getElementById('tools-meta');
        if (meta) {
            meta.textContent = toolsTotal > toolsData.length
                ? `Loaded ${toolsData.length} of ${toolsTotal} tools. Use search to query the full catalog.`
                : `Loaded ${toolsData.length} tools.`;
        }
        return;
    }

    // For real catalog search, use the API. Keep local filtering for 1-char queries.
    if (q.length < 2) {
        const filtered = toolsData.filter(t =>
            t.name.toLowerCase().includes(q) ||
            t.description.toLowerCase().includes(q) ||
            t.category.toLowerCase().includes(q) ||
            (t.tags || []).some(tag => tag.includes(q))
        );
        renderTools(filtered);
        return;
    }

    if (lastToolSearchController) lastToolSearchController.abort();
    lastToolSearchController = new AbortController();
    const meta = document.getElementById('tools-meta');
    if (meta) meta.textContent = 'Searching...';

    apiFetch(`/api/tools?search=${encodeURIComponent(q)}&limit=200&offset=0`, { signal: lastToolSearchController.signal })
        .then(resp => resp.json().then(data => ({ ok: resp.ok, data })))
        .then(({ ok, data }) => {
            if (!ok) throw new Error(extractErrorMessage(data, 'search failed'));
            const rows = data.tools || [];
            renderTools(rows);
            if (meta) meta.textContent = `Found ${rows.length} result(s).`;
        })
        .catch(err => {
            if (String(err?.name || '').toLowerCase().includes('abort')) return;
            if (meta) meta.textContent = 'Search failed.';
            showToast(`Tool search failed: ${err.message || err}`, 'error');
        });
}


// ══════════════════════════════════════
// Utilities
// ══════════════════════════════════════

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    // Code blocks
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    // Bold & italic
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    // Headers
    html = html.replace(/^### (.+)$/gm, '<h4 style="color:var(--accent);margin:12px 0 6px">$1</h4>');
    html = html.replace(/^## (.+)$/gm, '<h3 style="color:var(--accent);margin:14px 0 8px">$1</h3>');
    html = html.replace(/^# (.+)$/gm, '<h2 style="color:var(--accent);margin:16px 0 10px">$1</h2>');
    // Lists
    html = html.replace(/^- (.+)$/gm, '<div style="padding-left:16px">• $1</div>');
    html = html.replace(/^\d+\. (.+)$/gm, '<div style="padding-left:16px">$1</div>');
    // Line breaks
    html = html.replace(/\n/g, '<br>');
    return html;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✅', error: '❌', info: 'ℹ️' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}

function extractErrorMessage(payload, fallback = 'unknown error') {
    if (!payload) return fallback;
    if (typeof payload === 'string') return payload || fallback;
    if (payload.message && typeof payload.message === 'string') return payload.message;
    if (typeof payload.detail === 'string') return payload.detail;
    if (payload.detail && typeof payload.detail === 'object') {
        if (typeof payload.detail.message === 'string') return payload.detail.message;
        if (Array.isArray(payload.detail)) {
            const first = payload.detail[0];
            if (first && typeof first.msg === 'string') return first.msg;
        }
    }
    if (payload.error && typeof payload.error === 'string') return payload.error;
    return fallback;
}
