// ===========================================================================
// Enko Web Console — Auth & API layer
// ===========================================================================

// ── Auth ───────────────────────────────────────────────────────────────────

const auth = {
  token: localStorage.getItem("enko_token") || null,
  username: localStorage.getItem("enko_user") || null,
  tier: localStorage.getItem("enko_tier") || "free",
  tierLimits: JSON.parse(localStorage.getItem("enko_tier_limits") || "null"),

  save(token, username, tier, tierLimits) {
    this.token = token;
    this.username = username;
    this.tier = tier || "free";
    this.tierLimits = tierLimits || null;
    localStorage.setItem("enko_token", token);
    localStorage.setItem("enko_user", username);
    localStorage.setItem("enko_tier", this.tier);
    if (tierLimits) localStorage.setItem("enko_tier_limits", JSON.stringify(tierLimits));
  },

  clear() {
    this.token = null;
    this.username = null;
    this.tier = "free";
    this.tierLimits = null;
    localStorage.removeItem("enko_token");
    localStorage.removeItem("enko_user");
    localStorage.removeItem("enko_tier");
    localStorage.removeItem("enko_tier_limits");
  },

  isPro() { return this.tier === "pro"; },

  canUseFeature(feature) {
    if (!this.tierLimits) return true;
    const allowed = this.tierLimits.features || [];
    return allowed.includes(feature);
  },

  headers() {
    const h = { "Content-Type": "application/json" };
    if (this.token) h["Authorization"] = `Bearer ${this.token}`;
    return h;
  },
};

// ── Authenticated fetch ───────────────────────────────────────────────────

async function authFetch(url, options = {}) {
  options.headers = { ...auth.headers(), ...(options.headers || {}) };
  const resp = await fetch(url, options);
  if (resp.status === 401) {
    auth.clear();
    showToast("会话已过期，请重新登录", "error");
    showLoginScreen();
    throw new Error("会话已过期，请重新登录");
  }
  if (resp.status === 403) {
    const data = await resp.clone().json().catch(() => null);
    if (data?.detail?.error_code === "TIER_RESTRICTED") {
      showToast(data.detail.message || "此功能需要升级专业版", "warning");
    } else {
      showToast(`[${resp.status}] 权限不足`, "error");
    }
  }
  if (resp.status >= 500) {
    showToast(`[${resp.status}] 服务器内部错误，请稍后重试`, "error");
  }
  if (resp.status === 429) {
    const retryAfter = parseInt(resp.headers.get("Retry-After") || "30", 10);
    _startRetryCountdown(retryAfter);
  }
  return resp;
}

/** Parse detail from API error responses (supports string and {message, error_code} formats). */
function parseApiError(data) {
  if (!data) return "未知错误";
  const detail = data.detail || data.error || data.message || data;
  if (typeof detail === "object" && detail.message) {
    return detail.error_code ? `[${detail.error_code}] ${detail.message}` : detail.message;
  }
  if (typeof data === "object" && data.error_code) {
    return `[${data.error_code}] ${String(detail)}`;
  }
  return String(detail);
}

// ── Rate limit countdown ──────────────────────────────────────────────────

let _retryTimer = null;
function _startRetryCountdown(seconds) {
  if (_retryTimer) clearInterval(_retryTimer);
  let remaining = seconds;
  showToast(`请求过于频繁，${remaining} 秒后可重试`, "error");
  _retryTimer = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(_retryTimer);
      _retryTimer = null;
      showToast("可以重新操作了", "success");
    }
  }, 1000);
}

// ── Login UI ──────────────────────────────────────────────────────────────

function showLoginScreen() {
  let overlay = document.getElementById("login-overlay");
  if (overlay) { overlay.style.display = "flex"; return; }

  overlay = document.createElement("div");
  overlay.id = "login-overlay";
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-card">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="width:48px;height:48px;margin:0 auto 12px;border-radius:12px;background:var(--c-gradient-primary);display:flex;align-items:center;justify-content:center;">
          <span class="material-symbols-outlined" style="color:#000;font-size:28px;font-variation-settings:'FILL' 1;">security</span>
        </div>
        <h2>哨兵控制台</h2>
        <p class="subtitle">APK 加固引擎</p>
      </div>
      <div id="login-error" class="modal-error"></div>
      <label>用户名</label>
      <input id="login-user" type="text" value="admin" />
      <label>密码</label>
      <input id="login-pass" type="password" style="margin-bottom:20px;" />
      <button id="login-btn" class="btn-primary">登 录</button>
    </div>`;
  document.body.appendChild(overlay);

  const btn = document.getElementById("login-btn");
  const passInput = document.getElementById("login-pass");
  btn.addEventListener("click", doLogin);
  passInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
}

async function doLogin() {
  const userEl = document.getElementById("login-user");
  const passEl = document.getElementById("login-pass");
  const errEl = document.getElementById("login-error");
  const btnEl = document.getElementById("login-btn");

  btnEl.disabled = true;
  btnEl.textContent = "登录中...";
  errEl.style.display = "none";

  try {
    const resp = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: userEl.value, password: passEl.value }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(parseApiError(data));
    auth.save(data.token, data.username, data.tier, data.tier_limits);
    document.getElementById("login-overlay").style.display = "none";
    init();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = "block";
  } finally {
    btnEl.disabled = false;
    btnEl.textContent = "登 录";
  }
}

// ── Password change ───────────────────────────────────────────────────────

function showPasswordChangeDialog() {
  let overlay = document.getElementById("password-overlay");
  if (overlay) { overlay.style.display = "flex"; return; }
  overlay = document.createElement("div");
  overlay.id = "password-overlay";
  overlay.className = "modal-overlay";
  overlay.style.background = "rgba(6,14,32,0.85)";
  overlay.style.backdropFilter = "blur(8px)";
  overlay.innerHTML = `
    <div class="modal-card" style="padding:32px;">
      <h3 style="font-size:16px;margin:0 0 16px;">修改密码</h3>
      <div id="pwd-error" class="modal-error"></div>
      <label>当前密码</label>
      <input id="pwd-old" type="password" style="margin-bottom:10px;" />
      <label>新密码 (至少8位)</label>
      <input id="pwd-new" type="password" style="margin-bottom:10px;" />
      <label>确认新密码</label>
      <input id="pwd-confirm" type="password" style="margin-bottom:16px;" />
      <div style="display:flex;gap:8px;">
        <button id="pwd-cancel" class="btn-secondary">取消</button>
        <button id="pwd-submit" class="btn-primary" style="flex:1;">确认修改</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("pwd-cancel").addEventListener("click", () => overlay.style.display = "none");
  document.getElementById("pwd-submit").addEventListener("click", async () => {
    const errEl = document.getElementById("pwd-error");
    const oldPwd = document.getElementById("pwd-old").value;
    const newPwd = document.getElementById("pwd-new").value;
    const confirm = document.getElementById("pwd-confirm").value;
    errEl.style.display = "none";
    if (newPwd !== confirm) { errEl.textContent = "两次密码不一致"; errEl.style.display = "block"; return; }
    if (newPwd.length < 8) { errEl.textContent = "新密码至少8位"; errEl.style.display = "block"; return; }
    try {
      const resp = await authFetch("/api/auth/change-password", {
        method: "POST", body: JSON.stringify({ old_password: oldPwd, new_password: newPwd }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(parseApiError(data));
      overlay.style.display = "none";
      showToast("密码修改成功", "success");
    } catch (e) { errEl.textContent = e.message; errEl.style.display = "block"; }
  });
}

// ── Authenticated job download ────────────────────────────────────────────

async function handleAuthDownload(event) {
  event.preventDefault();
  if (!state.activeJobId) { showToast("没有可下载的任务", "warning"); return; }
  const btn = document.getElementById("jobDownloadBtn");
  const origHTML = btn ? btn.innerHTML : "";
  if (btn) {
    btn.innerHTML = '<span class="material-symbols-outlined text-lg animate-spin">progress_activity</span><span>准备下载...</span>';
    btn.style.pointerEvents = "none";
  }
  try {
    const tokenResp = await authFetch(`/api/jobs/${encodeURIComponent(state.activeJobId)}/download-token`, { method: "POST" });
    let dlUrl = `/api/jobs/${encodeURIComponent(state.activeJobId)}/download`;
    if (tokenResp.ok) {
      const { token } = await tokenResp.json();
      dlUrl += `?dl_token=${encodeURIComponent(token)}`;
    } else if (tokenResp.status !== 404) {
      const errData = await tokenResp.json().catch(() => ({}));
      showToast("下载失败: " + parseApiError(errData), "error");
      return;
    }
    const a = document.createElement("a");
    a.href = dlUrl;
    a.download = `${state.activeJobId}-hardened.apk`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    showToast("下载已开始", "success");
  } catch (e) { showToast("下载失败: " + e.message, "error"); }
  finally {
    if (btn) { btn.innerHTML = origHTML; btn.style.pointerEvents = ""; }
  }
}
window.handleAuthDownload = handleAuthDownload;

// ── WebSocket job streaming ───────────────────────────────────────────────

let _jobWs = null;
let _wsReconnectTimer = null;
let _wsReconnectAttempts = 0;
let _wsManualClose = false;
let _wsFallbackShown = false;
let _wsBannerTimer = null;
const _WS_MAX_RECONNECT = 8;

function connectJobWebSocket(jobId) {
  if (!state.websocketAvailable) {
    const indicator = document.getElementById("wsIndicator");
    if (indicator) {
      indicator.classList.remove("bg-secondary", "bg-yellow-500");
      indicator.classList.add("bg-slate-600");
      indicator.title = "当前服务使用轮询同步任务";
    }
    hideWsBanner();
    return;
  }
  disconnectJobWebSocket({ silent: true });
  _wsManualClose = false;
  _wsFallbackShown = false;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/api/jobs/${jobId}/ws?token=${encodeURIComponent(auth.token)}`;
  try {
    _jobWs = new WebSocket(url);
  } catch { startPolling(); return; }

  const indicator = document.getElementById("wsIndicator");

  _jobWs.onopen = () => {
    _wsReconnectAttempts = 0;
    if (indicator) { indicator.classList.remove("bg-slate-600", "bg-yellow-500"); indicator.classList.add("bg-secondary"); indicator.title = "WebSocket 已连接"; }
    hideWsBanner();
  };
  _jobWs.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "log") {
        const logEl = document.getElementById("jobLog");
        if (logEl) { logEl.textContent += (logEl.textContent ? "\n" : "") + msg.line; logEl.scrollTop = logEl.scrollHeight; }
        if (msg.progress != null) updateProgress(msg.progress, msg.progress_label);
      } else if (msg.type === "status") {
        if (msg.status) {
          const badge = document.getElementById("jobStatusBadge");
          if (badge) badge.textContent = statusLabel(msg.status);
        }
        if (msg.progress != null) updateProgress(msg.progress, msg.progress_label);
      } else if (msg.type === "finished") {
        updateProgress(100, "完成");
        disconnectJobWebSocket({ completed: true, silent: true });
        pollJob();
      } else if (msg.type === "ping") {
        // Keep-alive from server, no action needed
      }
    } catch {}
  };
  _jobWs.onclose = () => {
    if (_wsManualClose) {
      _wsManualClose = false;
      if (indicator) {
        indicator.classList.remove("bg-secondary", "bg-yellow-500");
        indicator.classList.add("bg-slate-600");
      }
      return;
    }
    if (indicator) { indicator.classList.remove("bg-secondary"); indicator.classList.add("bg-yellow-500"); indicator.title = "实时通道不可用，已切换轮询"; }
    if (state.activeJobId) {
      _wsReconnectAttempts++;
      if (_wsReconnectAttempts <= _WS_MAX_RECONNECT) {
        const delay = Math.min(1000 * Math.pow(2, _wsReconnectAttempts - 1), 10000);
        showWsBanner(`实时通道暂不可用，${(delay/1000).toFixed(0)}秒后重连（${_wsReconnectAttempts}/${_WS_MAX_RECONNECT}）`, "warning");
        _wsReconnectTimer = setTimeout(() => connectJobWebSocket(jobId), delay);
      } else {
        showWsBanner("实时通道不可用，已使用轮询同步任务", "info");
        startPolling();
      }
    }
  };
  _jobWs.onerror = () => {
    if (!_wsFallbackShown) {
      showWsBanner("实时通道不可用，已使用轮询同步任务", "info");
      _wsFallbackShown = true;
    }
    disconnectJobWebSocket();
    startPolling();
  };
}

function disconnectJobWebSocket(options = {}) {
  const { completed = false, silent = false } = options;
  if (_wsReconnectTimer) { clearTimeout(_wsReconnectTimer); _wsReconnectTimer = null; }
  if (_jobWs) {
    _wsManualClose = true;
    try { _jobWs.close(); } catch {}
    _jobWs = null;
  }
  const indicator = document.getElementById("wsIndicator");
  if (indicator) {
    indicator.classList.remove("bg-secondary", "bg-yellow-500");
    indicator.classList.add("bg-slate-600");
    indicator.title = completed ? "任务已完成，实时通道已关闭" : "实时通道未连接";
  }
  if (silent) hideWsBanner();
}

function showWsBanner(msg, type) {
  let banner = document.getElementById("wsBanner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "wsBanner";
    banner.className = "fixed top-0 left-0 right-0 z-[9998] text-center text-xs py-1.5 transition-all";
    document.body.prepend(banner);
  }
  banner.textContent = msg;
  banner.className = banner.className.replace(/bg-\S+/g, "");
  banner.classList.add(type === "warning" ? "bg-yellow-600" : "bg-blue-600");
  banner.classList.remove("hidden");
  if (_wsBannerTimer) {
    clearTimeout(_wsBannerTimer);
    _wsBannerTimer = null;
  }
  if (type === "info") {
    _wsBannerTimer = setTimeout(hideWsBanner, 5000);
  }
}
function hideWsBanner() {
  if (_wsBannerTimer) {
    clearTimeout(_wsBannerTimer);
    _wsBannerTimer = null;
  }
  const banner = document.getElementById("wsBanner");
  if (banner) banner.classList.add("hidden");
}
