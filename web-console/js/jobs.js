// ===========================================================================
// Enko Web Console — Dashboard, job list, job detail, and polling helpers
// ===========================================================================

function updateProgress(pct, label) {
  const container = document.getElementById("jobProgressContainer");
  const bar = document.getElementById("jobProgressBar");
  const lbl = document.getElementById("jobProgressLabel");
  const pctEl = document.getElementById("jobProgressPct");
  if (!container) return;
  container.classList.remove("hidden");
  if (bar) bar.style.width = `${Math.min(100, pct)}%`;
  if (lbl && label) lbl.textContent = label;
  if (pctEl) pctEl.textContent = `${pct}%`;
}

function hideProgress() {
  const container = document.getElementById("jobProgressContainer");
  if (container) container.classList.add("hidden");
}

function jobStatusMeta(status) {
  const map = {
    succeeded: { label: "成功", cls: "bg-secondary/10 text-secondary", badge: "good" },
    failed: { label: "失败", cls: "bg-error/10 text-error", badge: "bad" },
    running: { label: "运行中", cls: "bg-primary/10 text-primary", badge: "warn" },
    queued: { label: "排队中", cls: "bg-slate-700/50 text-slate-300", badge: "idle" },
    idle: { label: "空闲", cls: "bg-slate-700/50 text-slate-300", badge: "idle" },
  };
  return map[status] || { label: status || "未知", cls: "bg-slate-700/50 text-slate-300", badge: "idle" };
}

function jobScoreMarkup(job) {
  const score = job.report_score ?? job.score;
  const grade = job.report_grade ?? job.grade ?? "";
  return score != null
    ? `<span class="font-bold">${escapeHtml(String(score))}</span><span class="text-slate-500 text-[10px] ml-1">${escapeHtml(String(grade))}</span>`
    : '<span class="text-slate-500">—</span>';
}

function formatJobTime(value) {
  return value
    ? new Date(value).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
    : "—";
}

async function loadDashboardStats() {
  ["dash-total-apk", "dash-avg-score", "dash-success-rate"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.add("dash-loading");
  });
  try {
    const resp = await authFetch("/api/stats");
    if (!resp.ok) {
      showDashError("dash-stats-error", "统计数据加载失败");
      return;
    }
    hideDashError("dash-stats-error");
    const data = await resp.json();
    const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
    set("dash-total-apk", data.total_jobs ?? "—");
    set("dash-avg-score", data.avg_score != null ? data.avg_score.toFixed(1) : "—");

    const rate = data.success_rate;
    const rateEl = document.getElementById("dash-success-rate");
    const rateIcon = document.getElementById("dash-success-icon");
    const rateNote = document.getElementById("dash-success-note");
    if (rate != null && rateEl) {
      const pct = (rate * 100).toFixed(0);
      rateEl.textContent = `${pct}%`;
      rateEl.classList.remove("text-secondary", "text-yellow-500", "text-error", "text-slate-400");
      if (rateIcon) rateIcon.classList.remove("bg-secondary/10", "text-secondary", "bg-yellow-500/10", "text-yellow-500", "bg-error/10", "text-error", "bg-slate-800", "text-slate-400");
      if (pct >= 80) {
        rateEl.classList.add("text-secondary");
        if (rateIcon) rateIcon.classList.add("bg-secondary/10", "text-secondary");
        if (rateNote) rateNote.textContent = "运行良好";
      } else if (pct >= 50) {
        rateEl.classList.add("text-yellow-500");
        if (rateIcon) rateIcon.classList.add("bg-yellow-500/10", "text-yellow-500");
        if (rateNote) rateNote.textContent = "需关注失败任务";
      } else {
        rateEl.classList.add("text-error");
        if (rateIcon) rateIcon.classList.add("bg-error/10", "text-error");
        if (rateNote) rateNote.textContent = "失败率较高";
      }
    }

    set("dash-today-tasks", data.today_jobs ?? 0);
    set("dash-today-detail", `${data.today_succeeded ?? 0} 完成 / ${data.today_running ?? 0} 运行中`);
    set("dash-today-count", data.today_jobs ?? 0);

    const gd = data.grade_distribution || {};
    set("dash-grade-a", `A 级 (${gd["A"] || 0})`);
    set("dash-grade-b", `B 级 (${gd["B"] || 0})`);
    set("dash-grade-c", `C 级 (${gd["C"] || 0})`);
    set("dash-grade-d", `D 级 (${gd["D"] || 0})`);

    const total = data.total_jobs || 1;
    const gradePct = ((gd["A"] || 0) + (gd["B"] || 0)) / total * 100;
    set("dash-grade-pct", `${gradePct.toFixed(0)}%`);
    const gauge = document.querySelector(".radial-gauge");
    if (gauge) gauge.style.background = `conic-gradient(from 180deg at 50% 50%, #69f6b8 0%, #69f6b8 ${gradePct}%, #192540 ${gradePct}%, #192540 100%)`;

    const avgBar = document.getElementById("dash-avg-bar");
    if (avgBar && data.avg_score != null) avgBar.style.width = `${Math.min(data.avg_score, 100)}%`;
    const avgNote = document.getElementById("dash-avg-note");
    if (avgNote && data.avg_score != null) avgNote.textContent = data.avg_score >= 80 ? "安全等级优秀" : data.avg_score >= 60 ? "安全等级良好" : "安全等级待提高";
    set("dash-total-trend", data.total_jobs > 0 ? `已完成 ${data.succeeded ?? 0} 次` : "—");

    renderDashboardJobs(data.recent_jobs || []);
  } catch {
    showDashError("dash-stats-error", "网络异常，无法加载统计");
  } finally {
    ["dash-total-apk", "dash-avg-score", "dash-success-rate"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.remove("dash-loading");
    });
  }
}

function renderDashboardJobs(jobs) {
  const tbody = document.getElementById("dash-jobs-tbody");
  if (!tbody) return;
  if (!jobs || jobs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-12 text-center">
      <div class="empty-state empty-state-enhanced"><span class="material-symbols-outlined empty-state-float">inbox</span>
      <p class="text-sm font-medium text-on-surface mb-1">暂无任务记录</p>
      <p class="text-xs text-on-surface-variant">开始一个新的加固任务吧</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = jobs.map(j => {
    const st = jobStatusMeta(j.status);
    const score = jobScoreMarkup(j);
    const time = formatJobTime(j.created_at);
    const canDelete = j.status === "succeeded" || j.status === "failed";
    const delBtn = canDelete ? `<button onclick="event.stopPropagation(); deleteDashboardJob('${j.id}')" class="text-slate-500 hover:text-error transition-colors p-1 rounded" title="删除任务"><span class="material-symbols-outlined text-sm">delete</span></button>` : "";
    return `<tr class="hover:bg-surface-container-high/30 transition-colors cursor-pointer" onclick="viewJobDetail('${j.id}')">
      <td class="px-6 py-4"><span class="text-sm font-medium text-on-surface">${j.id.slice(0, 12)}</span></td>
      <td class="px-6 py-4"><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${st.cls}">${st.label}</span></td>
      <td class="px-6 py-4 text-sm">${score}</td>
      <td class="px-6 py-4 text-xs text-slate-400">${time}</td>
      <td class="px-4 py-4 text-right">${delBtn}</td></tr>`;
  }).join("");
}

let _jobsCache = [];

async function loadJobsPage() {
  const tbody = document.getElementById("jobsListTbody");
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-12 text-center text-sm text-on-surface-variant">正在加载任务...</td></tr>`;
  }
  try {
    const resp = await authFetch("/api/jobs");
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(parseApiError(data) || "任务列表加载失败");
    }
    const data = await resp.json();
    _jobsCache = data.jobs || [];
    renderJobsPage();
  } catch (error) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-12 text-center text-sm text-error">${escapeHtml(error.message)}</td></tr>`;
    }
  }
}

function renderJobsPage() {
  const tbody = document.getElementById("jobsListTbody");
  if (!tbody) return;
  const search = (document.getElementById("jobsSearchInput")?.value || "").trim().toLowerCase();
  const status = document.getElementById("jobsStatusFilter")?.value || "all";
  const rows = _jobsCache.filter(job => {
    if (status !== "all" && job.status !== status) return false;
    if (!search) return true;
    const haystack = [
      job.id,
      job.status,
      job.input_apk,
      job.output_apk,
      job.report_json,
      job.command_preview,
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(search);
  });

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-12 text-center">
      <div class="empty-state"><span class="material-symbols-outlined">inbox</span>
      <p class="text-sm font-medium text-on-surface mb-1">没有匹配的任务</p>
      <p class="text-xs text-on-surface-variant">调整筛选条件或新建一个任务</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(job => {
    const st = jobStatusMeta(job.status);
    const features = buildFeatureSummary(job.features || {});
    const created = formatJobTime(job.created_at);
    const canDelete = job.status === "succeeded" || job.status === "failed";
    const delBtn = canDelete
      ? `<button onclick="event.stopPropagation(); deleteDashboardJob('${job.id}')" class="text-slate-500 hover:text-error transition-colors p-1 rounded" title="删除任务"><span class="material-symbols-outlined text-sm">delete</span></button>`
      : "";
    return `<tr class="hover:bg-surface-container-high/30 transition-colors cursor-pointer" onclick="viewJobDetail('${job.id}')">
      <td class="px-5 py-4">
        <div class="text-sm font-medium text-on-surface font-mono">${escapeHtml(String(job.id || "").slice(0, 12))}</div>
        <div class="text-[10px] text-slate-500 truncate max-w-[280px]">${escapeHtml(job.output_apk || job.input_apk || "未生成输出路径")}</div>
      </td>
      <td class="px-5 py-4"><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${st.cls}">${st.label}</span></td>
      <td class="px-5 py-4 text-xs text-slate-400">${escapeHtml(features)}</td>
      <td class="px-5 py-4 text-sm">${jobScoreMarkup(job)}</td>
      <td class="px-5 py-4 text-xs text-slate-400">${created}</td>
      <td class="px-5 py-4 text-right">${delBtn}</td>
    </tr>`;
  }).join("");
}

async function viewJobDetail(jobId) {
  state.activeJobId = jobId;
  localStorage.setItem("enko_active_job", jobId);
  navigateTo("job-detail");
  try {
    const resp = await authFetch(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (resp.ok) {
      const data = await resp.json();
      renderJob(data.job);
      if (data.job.status === "running" || data.job.status === "queued") {
        connectJobWebSocket(jobId);
        startPolling();
      } else {
        disconnectJobWebSocket({ completed: true, silent: true });
        stopPolling();
      }
    }
  } catch (error) {
    showToast("任务详情加载失败: " + error.message, "error");
  }
}
window.viewJobDetail = viewJobDetail;

async function deleteDashboardJob(jobId) {
  if (!confirm("确认删除该任务记录？")) return;
  try {
    const resp = await authFetch(`/api/jobs/${encodeURIComponent(jobId)}`, { method: "DELETE" });
    if (!resp.ok) { showToast("删除失败", "error"); return; }
    showToast("已删除", "success");
    loadDashboardStats();
    loadJobsPage();
  } catch { showToast("删除失败", "error"); }
}
window.deleteDashboardJob = deleteDashboardJob;

async function loadEngineStatus() {
  try {
    const resp = await authFetch("/api/health");
    if (!resp.ok) {
      showDashError("dash-engine-error", "引擎状态加载失败");
      return;
    }
    hideDashError("dash-engine-error");
    const data = await resp.json();
    const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
    set("dash-engine-version", data.version || "—");
    const healthPct = data.ok ? "100%" : "0%";
    set("dash-health-pct", healthPct);
    const bar = document.getElementById("dash-health-bar");
    if (bar) bar.style.width = data.ok ? "100%" : "0%";
    set("dash-status-1", data.db_connected ? "✓ 数据库连接正常" : "✗ 数据库未连接");
    set("dash-status-2", data.shellApkAvailable ? "✓ Shell APK 已就绪" : "✗ Shell APK 未构建");
    set("dash-status-3", data.defaults?.ndk ? "✓ NDK 已配置" : "△ NDK 未检测到");
    document.querySelectorAll("#dash-status-1, #dash-status-2, #dash-status-3").forEach(el => {
      const icon = el.previousElementSibling;
      if (icon && el.textContent.startsWith("✓")) {
        icon.textContent = "check_circle";
        icon.classList.remove("text-slate-500"); icon.classList.add("text-secondary");
      } else if (icon && el.textContent.startsWith("✗")) {
        icon.textContent = "cancel";
        icon.classList.remove("text-slate-500"); icon.classList.add("text-error");
      }
    });
  } catch {
    showDashError("dash-engine-error", "网络异常，无法获取引擎状态");
  }
}

function showDashError(id, msg) {
  let el = document.getElementById(id);
  if (!el) {
    el = document.createElement("div");
    el.id = id;
    el.className = "text-xs text-error bg-error/10 rounded px-3 py-1.5 mt-2";
    const container = document.getElementById("view-dashboard");
    if (container) container.prepend(el);
  }
  el.textContent = "⚠ " + msg;
  el.classList.remove("hidden");
}

function hideDashError(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add("hidden");
}

function startPolling() {
  stopPolling();
  pollJob();
  state.pollTimer = window.setInterval(pollJob, 8000);
}

function stopPolling() {
  if (state.pollTimer !== null) {
    window.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

async function pollJob() {
  if (!state.activeJobId) {
    return;
  }

  try {
    const response = await authFetch(`/api/jobs/${encodeURIComponent(state.activeJobId)}`);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(parseApiError(payload) || "查询任务状态失败");
    }
    const payload = await response.json();

    renderJob(payload.job);
    if (payload.job.status === "succeeded" || payload.job.status === "failed") {
      stopPolling();
      localStorage.removeItem("enko_active_job");
      loadDashboardStats();
      loadJobsPage();
    }
  } catch (error) {
    showWsBanner(`状态同步暂时失败，继续轮询：${error.message}`, "info");
  }
}

function renderJob(job) {
  const safeJob = job || {};
  const jobStatus = safeJob.status || "idle";
  const statusMeta = jobStatusMeta(jobStatus);
  const badgeClass = statusMeta.badge;

  if (safeJob.id) {
    state.activeJobId = safeJob.id;
  }

  if (els.jobStatusBadge) {
    els.jobStatusBadge.textContent = statusLabel(jobStatus);
    els.jobStatusBadge.className = `badge status-badge ${badgeClass}`;
  }
  if (els.jobIdValue) els.jobIdValue.textContent = safeJob.id || "-";
  if (els.jobReturnCode) els.jobReturnCode.textContent =
    safeJob.returncode === null || safeJob.returncode === undefined ? "-" : String(safeJob.returncode);
  if (els.jobDuration) els.jobDuration.textContent = buildDurationText(safeJob);
  if (els.jobOutputApk) els.jobOutputApk.textContent = safeJob.output_apk || "-";
  if (els.jobReportPath) els.jobReportPath.textContent = safeJob.report_json || "-";
  if (els.jobCommandPreview) {
    els.jobCommandPreview.textContent = safeJob.command_preview || "选择一个任务后，这里会显示实际执行命令。";
  }
  if (els.jobLog) {
    els.jobLog.textContent = (safeJob.log || []).join("\n") || "选择一个任务后，这里会显示加固日志。";
  }

  const toolSummary = buildToolSummary(safeJob.resolved_tools || state.environment, safeJob.resolved_ndk || resolveNdkPath(els.ndkPath.value));
  const scoreGateSummary = buildScoreGateSummary(safeJob);
  const report = safeJob.report && typeof safeJob.report === "object" ? safeJob.report : null;

  if (els.jobMetaList) renderStackList(els.jobMetaList, [
    {
      title: "当前状态",
      body: describeStatus(jobStatus, safeJob.error),
      state: jobStatus === "succeeded" ? "enabled" : jobStatus === "running" ? "partial" : jobStatus === "failed" ? "missing" : "partial",
    },
    {
      title: "功能选择",
      body: buildFeatureSummary(safeJob.features || state.features),
      state: "enabled",
    },
    {
      title: "工具链",
      body: toolSummary,
      state: toolSummary === "未解析" ? "partial" : "enabled",
    },
    {
      title: "Score Gate",
      body: scoreGateSummary,
      state: scoreGateSummary.includes("->") ? "partial" : "enabled",
    },
    {
      title: "命令入口",
      body: safeJob.command_preview || "尚未启动",
      state: safeJob.command_preview ? "enabled" : "partial",
    },
  ]);

  if (els.jobReportSummaryList) {
    renderStackList(els.jobReportSummaryList, buildJobReportSummary(safeJob, report));
  }

  if (els.jobLog) {
    els.jobLog.scrollTop = els.jobLog.scrollHeight;
  }

  if (jobStatus === "running" || jobStatus === "queued") {
    updateProgress(safeJob.progress || 0, safeJob.progress_label || "执行中...");
  } else if (jobStatus === "succeeded" || jobStatus === "failed") {
    hideProgress();
    disconnectJobWebSocket({ completed: true, silent: true });
  }

  const dlArea = document.getElementById("jobDownloadArea");
  const dlBtn = document.getElementById("jobDownloadBtn");
  if (dlArea && dlBtn) {
    if (jobStatus === "succeeded" && safeJob.id && safeJob.output_exists !== false) {
      dlArea.classList.remove("hidden");
      dlBtn.href = "#";
    } else {
      dlArea.classList.add("hidden");
    }
  }

  if (jobStatus === "succeeded" && report) {
    renderReport(report);
  }
}

function buildFeatureSummary(features) {
  const labels = [];
  if (features.extract) {
    labels.push("Extract");
  }
  if (features.vmpDex || features.vmp_dex) {
    labels.push("VMP DEX");
  }
  if (features.dex2c) {
    labels.push("DEX2C");
  }
  const vmpPreset = features.vmpObfuscationPreset || features.vmp_obfuscation_preset;
  if ((features.vmpDex || features.vmp_dex || features.vmpShellDex) && vmpPreset && vmpPreset !== "stable") {
    labels.push(`VMP ${vmpPreset}`);
  }
  if (features.dex2c && (features.dex2cOllvm ?? features.dex2c_ollvm)) {
    labels.push(features.dex2cOllvmRequired || features.dex2c_ollvm_required ? "OLLVM required" : "OLLVM");
  }
  if (features.signingEnabled || features.signing_enabled) {
    labels.push("Signed");
  } else if (features.signingEnabled === false || features.signing_enabled === false) {
    labels.push("External signing");
  }
  if (features.commercialMode || features.commercial_mode) {
    labels.push("Commercial");
  }
  if (features.releaseManifestEnabled || features.release_manifest_enabled) {
    labels.push("Release Manifest");
  }
  if (features.perApkKey === false || features.per_apk_key === false) {
    labels.push("Shared key");
  }
  return labels.length ? labels.join(" / ") : "无";
}

function buildToolSummary(tools, ndkPath) {
  const labels = [];
  if (tools.apktool) {
    labels.push("apktool");
  }
  if (tools.zipalign) {
    labels.push("zipalign");
  }
  if (tools.apksigner) {
    labels.push("apksigner");
  }
  if (ndkPath) {
    labels.push("ndk");
  }
  return labels.length ? labels.join(" / ") : "未解析";
}

function buildScoreGateSummary(job) {
  const requested = asNumber(job.min_score_requested);
  const effective = asNumber(job.min_score_effective);
  if (!requested && !effective) {
    return "未设置";
  }
  if (requested && effective && requested !== effective) {
    return `${requested} -> ${effective}（已按签名/模式自动收敛）`;
  }
  return String(effective || requested);
}
