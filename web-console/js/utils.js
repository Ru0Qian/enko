// ===========================================================================
// Enko Web Console — Utility functions
// ===========================================================================

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const colors = {
    success: "bg-secondary/90 text-on-secondary-fixed border-secondary/30",
    error: "bg-error/90 text-white border-error/30",
    warning: "bg-yellow-600/90 text-white border-yellow-500/30",
    info: "bg-primary/90 text-on-primary-fixed border-primary/30",
  };
  const icons = { success: "check_circle", error: "error", warning: "warning", info: "info" };
  const toast = document.createElement("div");
  toast.className = `pointer-events-auto flex items-center gap-3 px-5 py-3.5 rounded-xl border text-sm font-medium shadow-xl backdrop-blur-md ${colors[type] || colors.info}`;
  toast.style.animation = "toastSlideIn 0.35s cubic-bezier(0.34,1.56,0.64,1) forwards";
  toast.innerHTML = `<span class="material-symbols-outlined text-base" style="font-variation-settings:'FILL' 1">${icons[type] || "info"}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "toastSlideOut 0.3s ease-in forwards";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function asNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function formatClock(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function percent(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "0.0%";
  }
  return `${(value * 100).toFixed(1)}%`;
}

function stateClass(stateValue) {
  if (stateValue === "enabled") {
    return "good";
  }
  if (stateValue === "partial") {
    return "warn";
  }
  return "bad";
}

function labelState(stateValue) {
  if (stateValue === "enabled") {
    return "已启用";
  }
  if (stateValue === "partial") {
    return "进行中";
  }
  return "缺失";
}

function highlightField(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.classList.add("ring-2", "ring-error");
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  setTimeout(() => el.classList.remove("ring-2", "ring-error"), 3000);
}

function showFieldError(elementId, message) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.classList.add("field-error");
  let msgEl = el.parentElement && el.parentElement.querySelector(`.field-error-msg[data-for="${elementId}"]`);
  if (!msgEl) {
    msgEl = document.createElement("span");
    msgEl.className = "field-error-msg";
    msgEl.setAttribute("data-for", elementId);
    el.insertAdjacentElement("afterend", msgEl);
  }
  msgEl.textContent = message;
  const timer = setTimeout(() => clearFieldError(elementId), 5000);
  el._fieldErrorTimer = timer;
}

function clearFieldError(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.classList.remove("field-error");
  if (el._fieldErrorTimer) { clearTimeout(el._fieldErrorTimer); el._fieldErrorTimer = null; }
  const msgEl = el.parentElement && el.parentElement.querySelector(`.field-error-msg[data-for="${elementId}"]`);
  if (msgEl) msgEl.remove();
}

function describeStatus(status, error) {
  if (status === "running") {
    return "任务正在执行，本地服务会持续刷新日志。";
  }
  if (status === "succeeded") {
    return "加固已完成！点击下方按钮下载加固后的 APK。";
  }
  if (status === "failed") {
    return error || "任务失败，请先看日志里报错位置。";
  }
  return "还没有启动任务。";
}

function buildDurationText(job) {
  if (!job.started_at) {
    if (job.status === "queued") return "排队等待中...";
    return "尚未执行";
  }
  const startDate = new Date(job.started_at);
  if (!job.finished_at) {
    const elapsed = Math.round((Date.now() - startDate.getTime()) / 1000);
    const mm = Math.floor(elapsed / 60);
    const ss = elapsed % 60;
    return `运行中 ${mm}:${String(ss).padStart(2, "0")} (开始于 ${formatClock(job.started_at)})`;
  }
  const endDate = new Date(job.finished_at);
  const dur = Math.round((endDate - startDate) / 1000);
  const mm = Math.floor(dur / 60);
  const ss = dur % 60;
  return `${formatClock(job.started_at)} → ${formatClock(job.finished_at)} (${mm}:${String(ss).padStart(2, "0")})`;
}

const _statusLabelsMap = { succeeded: "✅ 成功", failed: "❌ 失败", running: "⏳ 运行中", queued: "🕐 排队中", idle: "待提交" };
function statusLabel(status) {
  return _statusLabelsMap[status] || status || "未知";
}

// ---------------------------------------------------------------------------
// Number counting animation
// ---------------------------------------------------------------------------
function animateCount(el, target, duration = 800) {
  if (!el) return;
  const start = performance.now();
  const from = parseFloat(el.textContent) || 0;
  const targetNum = parseFloat(target);
  if (!Number.isFinite(targetNum)) {
    el.textContent = target;
    return;
  }
  el.classList.add("count-up");
  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // ease-out
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = from + (targetNum - from) * eased;
    el.textContent = Number.isInteger(targetNum)
      ? Math.round(current).toString()
      : current.toFixed(1);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ---------------------------------------------------------------------------
// Skeleton loading screen helpers
// ---------------------------------------------------------------------------
function showSkeleton(container) {
  if (!container) return;
  const tag = container.tagName.toLowerCase();
  const skeletons = {
    card: '<div class="skeleton skeleton-card"></div>',
    text: '<div><div class="skeleton skeleton-text"></div><div class="skeleton skeleton-text"></div><div class="skeleton skeleton-text"></div></div>',
    metric: '<div class="skeleton skeleton-metric"></div>',
    table: '<div class="skeleton skeleton-card" style="height:200px"></div>',
  };
  const html = skeletons[tag] || skeletons.card;
  container._skeletonOriginal = container.innerHTML;
  container.innerHTML = html;
  container.classList.add("skeleton-container");
}

function hideSkeleton(container) {
  if (!container || !container._skeletonOriginal) return;
  container.innerHTML = container._skeletonOriginal;
  delete container._skeletonOriginal;
  container.classList.remove("skeleton-container");
}
