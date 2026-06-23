// ===========================================================================
// Enko Web Console — Application core (state, UI, jobs, report, admin)
//
// Dependencies (loaded before this script):
//   js/utils.js    — showToast, escapeHtml, formatClock, buildDurationText, etc.
//   js/api.js      — auth, authFetch, showLoginScreen, WebSocket, etc.
//   js/analyzer.js — method analysis & protection map generation
//   js/report.js   — report rendering helpers
//   js/jobs.js     — dashboard, job list/detail, and polling helpers
// ===========================================================================

// Dashboard, jobs, and report rendering are split into js/jobs.js and js/report.js.
const state = {
  profile: "android_prod",
  target: "android",
  riskPolicy: "block",
  riskProfile: "strict",
  flutterMode: false,
  commercialMode: false,
  signingEnabled: false,
  signCertSha256: "",
  perApkKey: true,
  detectRoot: true,
  detectEmulator: true,
  protectDexPages: true,
  blockProxyVpn: true,
  releaseManifestEnabled: false,
  releaseManifestPath: "release/release_manifest.json",
  shellApk: "",
  outputApk: "",
  reportJsonPath: "",
  defaultShellApk: "",
  environment: {
    sdk_root: "",
    build_tools: "",
    ndk: "",
    apktool: "",
    zipalign: "",
    apksigner: "",
  },
  websocketAvailable: false,
  features: {
    extract: true,
    vmpDex: true,
    dex2c: true,
    vmpShellDex: false,
    polymorphicShell: false,
    aiDecoy: false,
  },
  extractOnDemand: true,
  autoProtectProfile: "balanced",
  vmpObfuscationPreset: "light",
  vmpVmTier: "auto",
  dex2cOllvm: true,
  dex2cOllvmRequired: false,
  dex2cOllvmClang: "",
  activeJobId: localStorage.getItem("enko_active_job") || null,
  pollTimer: null,
};
document.documentElement.dataset.enkoAppScript = "loaded";

const profileNames = {
  android_prod: "Android 生产",
  flutter_prod: "Flutter 生产",
  lab_debug: "实验室验证",
  custom: "自定义方案",
};

const gateDefinitions = [
  {
    title: "身份校验",
    desc: "包名和证书摘要先过 native 身份门闩，再允许后续逻辑继续。",
  },
  {
    title: "Shell DEX 完整性",
    desc: "壳 classes.dex 先验，防止直接改壳删调用链。",
  },
  {
    title: "Native 聚合完整性",
    desc: "先校验整组 native libs，再决定是否继续解密 payload。",
  },
  {
    title: "Flutter Core 完整性",
    desc: "Flutter 目标下，libapp.so 和 libflutter.so 会有独立门闩。",
  },
  {
    title: "回滚 / 重放",
    desc: "build-id、时间戳、版本号共同决定是否允许当前包继续运行。",
  },
  {
    title: "启动风险门",
    desc: "native anti-debug、anti-dump、hook 风险先决策，再决定是否放行。",
  },
];

const sampleReport = {
  score: 96,
  max_score: 100,
  grade: "A",
  risk_policy: "block",
  risk_profile: "strict",
  controls: [
    { name: "signed-output", points: 20, weight: 20, enabled: true, mode: "external-original-certificate", deferred: true },
    { name: "runtime-signature-pin", points: 15, weight: 15, enabled: true },
    { name: "per-apk-payload-key", points: 15, weight: 15, enabled: true },
    { name: "risk-policy-block", points: 10, weight: 10, enabled: true },
    { name: "risk-profile-strict", points: 10, weight: 10, enabled: true },
    { name: "method-protection-coverage", points: 4, weight: 5, enabled: true, coverage_grade: "B", role: "secondary" },
    { name: "flutter-native-core-integrity", points: 5, weight: 5, enabled: true, libapp_present: true, libflutter_present: true },
  ],
  recommendations: [],
  method_protection: {
    requested_total: 364,
    compiled_total: 283,
    protectable_methods_total: 4141,
    protectable_coverage_ratio: 0.0683,
    coverage_grade: "A",
    role: "secondary",
    vmp_bytecode_format: {
      blob_version: 4,
      instruction_encoding: "fixed8",
      instruction_width_bytes: 8,
      field_layout: ["opcode:u8", "dst:u8", "src1:u8", "src2:u8", "imm:s32"],
      field_layout_randomized: false,
      variable_length_supported: false,
      semantic_alias_handlers: true,
      semantic_alias_handler_variants: { "add-int": 10, "add-int/lit": 8 },
    },
  },
  target_runtime: {
    mode: "flutter",
    flutter_detected: true,
    native_core: {
      libapp: {
        present: true,
        path_count: 4,
        integrity_pinned: true,
      },
      libflutter: {
        present: true,
        path_count: 4,
        integrity_pinned: true,
      },
      hook_watch_targets: ["agpcore", "libapp.so", "libflutter.so"],
    },
  },
  compiled: {
    extract: 220,
    vmp_dex: 39,
    dex2c: 24,
  },
};

const els = {};

function refreshElements() {
  Object.assign(els, {
    heroGateCount: document.getElementById("heroGateCount"),
    heroMode: document.getElementById("heroMode"),
    heroPolicy: document.getElementById("heroPolicy"),
    profileBadge: document.getElementById("profileBadge"),
    inputApk: document.getElementById("inputApk"),
    shellApk: document.getElementById("shellApk"),
    outputApk: document.getElementById("outputApk"),
    ndkPath: document.getElementById("ndkPath"),
    protectionMap: document.getElementById("protectionMap"),
    reportJsonPath: document.getElementById("reportJsonPath"),
    featureExtract: document.getElementById("featureExtract"),
    featureVmpDex: document.getElementById("featureVmpDex"),
    featureDex2c: document.getElementById("featureDex2c"),
    featureVmpShellDex: document.getElementById("featureVmpShellDex"),
    featurePolymorphicShell: document.getElementById("featurePolymorphicShell"),
    featureAiDecoy: document.getElementById("featureAiDecoy"),
    extractOnDemand: document.getElementById("extractOnDemand"),
    methodSmartPreset: document.getElementById("methodSmartPreset"),
    vmpObfuscationPreset: document.getElementById("vmpObfuscationPreset"),
    vmpVmTier: document.getElementById("vmpVmTier"),
    dex2cOllvm: document.getElementById("dex2cOllvm"),
    dex2cOllvmRequired: document.getElementById("dex2cOllvmRequired"),
    dex2cOllvmClang: document.getElementById("dex2cOllvmClang"),
    abiArm64: document.getElementById("abiArm64"),
    abiArm32: document.getElementById("abiArm32"),
    abiX86_64: document.getElementById("abiX86_64"),
    abiX86: document.getElementById("abiX86"),
    commercialMode: document.getElementById("commercialMode"),
    flutterMode: document.getElementById("flutterMode"),
    signingEnabled: document.getElementById("signingEnabled"),
    signCertSha256: document.getElementById("signCertSha256"),
    perApkKey: document.getElementById("perApkKey"),
    detectRoot: document.getElementById("detectRoot"),
    detectEmulator: document.getElementById("detectEmulator"),
    protectDexPages: document.getElementById("protectDexPages"),
    blockProxyVpn: document.getElementById("blockProxyVpn"),
    releaseManifestEnabled: document.getElementById("releaseManifestEnabled"),
    releaseManifestPath: document.getElementById("releaseManifestPath"),
    releaseManifestBox: document.getElementById("releaseManifestBox"),
    minExtract: document.getElementById("minExtract"),
    minVmp: document.getElementById("minVmp"),
    minDex2c: document.getElementById("minDex2c"),
    minScore: document.getElementById("minScore"),
    keystorePath: document.getElementById("keystorePath"),
    ksPass: document.getElementById("ksPass"),
    keyAlias: document.getElementById("keyAlias"),
    keyPass: document.getElementById("keyPass"),
    commandPreview: document.getElementById("commandPreview"),
    copyCommand: document.getElementById("copyCommand"),
    startHardening: document.getElementById("startHardening"),
    signingBox: document.getElementById("signingBox"),
    externalSigningBox: document.getElementById("externalSigningBox"),
    gatesFlow: document.getElementById("gatesFlow"),
    reportFile: document.getElementById("reportFile"),
    loadSample: document.getElementById("loadSample"),
    scoreValue: document.getElementById("scoreValue"),
    gradeValue: document.getElementById("gradeValue"),
    modeValue: document.getElementById("modeValue"),
    policyValue: document.getElementById("policyValue"),
    coverageValue: document.getElementById("coverageValue"),
    coverageRole: document.getElementById("coverageRole"),
    nativeCoreValue: document.getElementById("nativeCoreValue"),
    hookTargetsValue: document.getElementById("hookTargetsValue"),
    controlsList: document.getElementById("controlsList"),
    nativeCoreList: document.getElementById("nativeCoreList"),
    methodStats: document.getElementById("methodStats"),
    recommendationsList: document.getElementById("recommendationsList"),
    jobStatusBadge: document.getElementById("jobStatusBadge"),
    jobIdValue: document.getElementById("jobIdValue"),
    jobReturnCode: document.getElementById("jobReturnCode"),
    jobDuration: document.getElementById("jobDuration"),
    jobOutputApk: document.getElementById("jobOutputApk"),
    jobReportPath: document.getElementById("jobReportPath"),
    jobMetaList: document.getElementById("jobMetaList"),
    jobReportSummaryList: document.getElementById("jobReportSummaryList"),
    jobCommandPreview: document.getElementById("jobCommandPreview"),
    jobLog: document.getElementById("jobLog"),
  });
}

async function init() {
  refreshElements();
  initShellNavigation();
  const authLoading = document.getElementById("auth-loading");
  // Check auth: if no token or token invalid, show login
  if (!auth.token) { if (authLoading) authLoading.remove(); showLoginScreen(); return; }
  try {
    const check = await fetch("/api/auth/check", { headers: auth.headers() });
    if (!check.ok) { auth.clear(); if (authLoading) authLoading.remove(); showLoginScreen(); return; }
    const checkData = await check.json();
    const usernameEl = document.getElementById("topbar-username");
    if (usernameEl && checkData.username) usernameEl.textContent = checkData.username;
    // Update tier from server (may have changed)
    if (checkData.tier) {
      auth.tier = checkData.tier;
      auth.tierLimits = checkData.tier_limits || null;
      localStorage.setItem("enko_tier", auth.tier);
      if (auth.tierLimits) localStorage.setItem("enko_tier_limits", JSON.stringify(auth.tierLimits));
    }
  } catch (_) {
    // server might not have auth (dev mode) — continue anyway
  }
  if (authLoading) authLoading.remove();

  bindProfileButtons();
  bindTargetButtons();
  bindPolicyButtons();
  bindRiskButtons();
  bindFields();
  if (typeof initMethodAnalysis === "function") initMethodAnalysis();
  initUploadZone();
  initNavigation();
  renderGates();
  await loadEnvironment();
  applyProfile(state.profile);
  renderReport(sampleReport);
  renderJob(null);

  // Restore active job from previous session
  if (state.activeJobId) {
    pollJob();
    startPolling();
  }

  // Load dashboard data
  loadDashboardStats();
  loadEngineStatus();
  loadJobsPage();

  // Apply tier-based UI restrictions
  applyTierUI();

  // Admin panel (show nav + load users if admin)
  initAdminPanel();
  if (auth.username === "admin") adminLoadUsers();

  // Bind password change / logout
  const changePwdBtn = document.getElementById("changePasswordBtn");
  if (changePwdBtn) changePwdBtn.addEventListener("click", showPasswordChangeDialog);
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => { auth.clear(); showLoginScreen(); });

  const jobsRefreshBtn = document.getElementById("jobsRefreshBtn");
  if (jobsRefreshBtn) jobsRefreshBtn.addEventListener("click", loadJobsPage);
  const jobsSearchInput = document.getElementById("jobsSearchInput");
  if (jobsSearchInput) jobsSearchInput.addEventListener("input", renderJobsPage);
  const jobsStatusFilter = document.getElementById("jobsStatusFilter");
  if (jobsStatusFilter) jobsStatusFilter.addEventListener("change", renderJobsPage);
  const jobRefreshBtn = document.getElementById("jobRefreshBtn");
  if (jobRefreshBtn) jobRefreshBtn.addEventListener("click", pollJob);

  // Accessibility: aria-live for toast container
  const toastC = document.getElementById("toast-container");
  if (toastC) { toastC.setAttribute("aria-live", "polite"); toastC.setAttribute("role", "status"); }

  // Accessibility: Escape key closes modals and overlays
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    // Close password change dialog
    const pwdOverlay = document.getElementById("pwd-overlay");
    if (pwdOverlay && pwdOverlay.style.display !== "none") { pwdOverlay.style.display = "none"; return; }
    // Close any visible modal overlay
    document.querySelectorAll(".modal-overlay").forEach(el => {
      if (el.id !== "login-overlay" && el.style.display !== "none") el.style.display = "none";
    });
  });
}

// ---------------------------------------------------------------------------
// Tier UI — lock features based on user tier
// ---------------------------------------------------------------------------
function applyTierUI() {
  const isPro = auth.isPro();
  const limits = auth.tierLimits || {};
  const allowedFeatures = new Set(limits.features || []);

  // Tier badge in topbar
  const topbar = document.getElementById("topbar-username");
  if (topbar) {
    const existingBadge = document.getElementById("tier-badge");
    if (existingBadge) existingBadge.remove();
    const badge = document.createElement("span");
    badge.id = "tier-badge";
    badge.className = isPro
      ? "ml-2 px-2 py-0.5 text-xs font-bold rounded-full bg-amber-500/20 text-amber-400"
      : "ml-2 px-2 py-0.5 text-xs font-bold rounded-full bg-surface-container text-on-surface-variant";
    badge.textContent = isPro ? "PRO" : "FREE";
    topbar.parentElement.appendChild(badge);
  }

  // Feature checkboxes: VMP and DEX2C locked for free
  const featureGates = [
    { el: els.featureVmpDex, feature: "vmpDex", label: "VMP 保护" },
    { el: els.featureDex2c, feature: "dex2c", label: "DEX2C" },
  ];

  featureGates.forEach(({ el, feature, label }) => {
    if (!el) return;
    const parent = el.closest("label");
    if (!parent) return;
    const lockId = `lock-${feature}`;
    const existingLock = parent.querySelector(`#${lockId}`);
    if (existingLock) existingLock.remove();

    if (!allowedFeatures.has(feature)) {
      el.checked = false;
      el.disabled = true;
      parent.classList.add("opacity-50", "cursor-not-allowed");
      parent.classList.remove("cursor-pointer");
      const lock = document.createElement("span");
      lock.id = lockId;
      lock.className = "material-symbols-outlined text-on-surface-variant ml-auto";
      lock.style.fontSize = "16px";
      lock.textContent = "lock";
      lock.title = `${label} 为专业版功能`;
      parent.appendChild(lock);
    } else {
      el.disabled = false;
      parent.classList.remove("opacity-50", "cursor-not-allowed");
      parent.classList.add("cursor-pointer");
    }
  });

  // Risk policy: block/exit locked for free
  document.querySelectorAll("[data-policy]").forEach(btn => {
    const policy = btn.getAttribute("data-policy");
    const allowed = limits.risk_policies ? new Set(limits.risk_policies) : new Set(["block", "degrade", "warn", "log", "off", "exit"]);
    const lockTarget = btn.closest("label") || btn;
    if (!allowed.has(policy)) {
      btn.disabled = true;
      lockTarget.classList.add("opacity-50", "cursor-not-allowed");
      lockTarget.title = `风险策略 "${policy}" 为专业版功能`;
      if (!lockTarget.querySelector(".lock-icon")) {
        lockTarget.insertAdjacentHTML("beforeend", '<span class="material-symbols-outlined lock-icon ml-auto" style="font-size:14px">lock</span>');
      }
    } else {
      btn.disabled = false;
      lockTarget.classList.remove("opacity-50", "cursor-not-allowed");
      lockTarget.title = "";
      const lockIcon = lockTarget.querySelector(".lock-icon");
      if (lockIcon) lockIcon.remove();
    }
  });

  // Risk profile: strict/balanced locked for free
  document.querySelectorAll("[data-risk]").forEach(btn => {
    const risk = btn.getAttribute("data-risk");
    const allowed = limits.risk_profiles ? new Set(limits.risk_profiles) : new Set(["compat", "balanced", "strict"]);
    const lockTarget = btn.closest("label") || btn;
    if (!allowed.has(risk)) {
      btn.disabled = true;
      lockTarget.classList.add("opacity-50", "cursor-not-allowed");
      lockTarget.title = `风险等级 "${risk}" 为专业版功能`;
      if (!lockTarget.querySelector(".lock-icon")) {
        lockTarget.insertAdjacentHTML("beforeend", '<span class="material-symbols-outlined lock-icon ml-auto" style="font-size:14px">lock</span>');
      }
    } else {
      btn.disabled = false;
      lockTarget.classList.remove("opacity-50", "cursor-not-allowed");
      lockTarget.title = "";
      const lockIcon = lockTarget.querySelector(".lock-icon");
      if (lockIcon) lockIcon.remove();
    }
  });

  // Additional toggles locked for free
  const toggleGates = [
    { el: els.signingEnabled, allowed: limits.allow_signing !== false, label: "加固端重签名" },
    { el: els.perApkKey, allowed: limits.allow_per_apk_key !== false, label: "独立密钥" },
    { el: els.commercialMode, allowed: limits.allow_commercial_mode !== false, label: "商业模式" },
    { el: els.releaseManifestEnabled, allowed: limits.allow_release_manifest !== false, label: "发布清单" },
  ];
  toggleGates.forEach(({ el, allowed, label }) => {
    if (!el) return;
    if (!allowed) {
      el.checked = false;
      el.disabled = true;
      const parent = el.closest("label") || el.parentElement;
      if (parent) {
        parent.classList.add("opacity-50");
        parent.title = `${label} 为专业版功能`;
      }
    } else {
      el.disabled = false;
      const parent = el.closest("label") || el.parentElement;
      if (parent) { parent.classList.remove("opacity-50"); parent.title = ""; }
    }
  });

  // Analyze button: locked for free tier
  const analyzeBtn = document.getElementById("analyzeMethodsBtn");
  if (analyzeBtn && !isPro) {
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add("opacity-50", "cursor-not-allowed");
    analyzeBtn.title = "智能方法分析为专业版功能";
  } else if (analyzeBtn) {
    analyzeBtn.disabled = false;
    analyzeBtn.classList.remove("opacity-50", "cursor-not-allowed");
    analyzeBtn.title = "分析 APK 并自动推荐保护映射表";
  }

  // Upgrade banner for free users
  const existingBanner = document.getElementById("tier-upgrade-banner");
  if (existingBanner) existingBanner.remove();
  if (!isPro) {
    const taskCard = document.querySelector("#view-new-job .glass-panel") || document.getElementById("view-new-job");
    if (taskCard) {
      const banner = document.createElement("div");
      banner.id = "tier-upgrade-banner";
      banner.className = "mx-6 mb-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center gap-3";
      banner.innerHTML = `
        <span class="material-symbols-outlined text-amber-400" style="font-size:20px;font-variation-settings:'FILL' 1">star</span>
        <span class="text-sm text-amber-200">当前为免费版 — VMP、DEX2C、加固端重签等高级功能需升级专业版</span>`;
      taskCard.insertBefore(banner, taskCard.firstChild);
    }
  }
}

async function loadEnvironment() {
  try {
    const response = await authFetch("/api/health");
    const payload = await response.json();
    if (!response.ok || !payload.defaults) {
      return;
    }
    state.environment = payload.defaults;
    state.defaultShellApk = payload.defaultShellApk || "";
    state.websocketAvailable = Boolean(payload.websocketAvailable);
    if (els.shellApk && !els.shellApk.value.trim() && state.defaultShellApk) {
      els.shellApk.value = state.defaultShellApk;
    }
    if (els.ndkPath && isPlaceholderNdk(els.ndkPath.value) && payload.defaults.ndk) {
      els.ndkPath.value = payload.defaults.ndk;
    }
  } catch (error) {
    console.warn("failed to load environment defaults", error);
  }
}

function maxReachableSecurityScore(config) {
  let score = 85;
  if (config.signingEnabled || config.signCertSha256) {
    score += 10;
  }
  if (config.commercialMode) {
    score += 15;
  }
  return Math.min(score, 100);
}

function normalizeScoreGate(config, syncField = false) {
  const normalized = { ...config };
  normalized.minScore = Math.max(0, normalized.minScore || 0);
  const maxReachable = maxReachableSecurityScore(normalized);
  if (normalized.minScore > maxReachable) {
    normalized.minScore = maxReachable;
  }
  if (syncField && els.minScore && asNumber(els.minScore.value) !== normalized.minScore) {
    els.minScore.value = normalized.minScore;
  }
  return normalized;
}

function bindProfileButtons() {
  document.querySelectorAll("[data-profile]").forEach((button) => {
    button.addEventListener("click", () => applyProfile(button.dataset.profile));
  });
}

function bindTargetButtons() {
  document.querySelectorAll("[data-target]").forEach((button) => {
    button.addEventListener("click", () => {
      state.target = button.dataset.target;
      state.flutterMode = state.target === "flutter";
      els.flutterMode.checked = state.flutterMode;
      syncGroup("[data-target]", state.target);
      scheduleRenderCommand();
    });
  });
}

function bindPolicyButtons() {
  document.querySelectorAll("[data-policy]").forEach((button) => {
    button.addEventListener("click", () => {
      state.riskPolicy = button.dataset.policy;
      syncGroup("[data-policy]", state.riskPolicy);
      scheduleRenderCommand();
    });
  });
}

function bindRiskButtons() {
  document.querySelectorAll("[data-risk]").forEach((button) => {
    button.addEventListener("click", () => {
      state.riskProfile = button.dataset.risk;
      syncGroup("[data-risk]", state.riskProfile);
      scheduleRenderCommand();
    });
  });
}

function bindFields() {
  [
    els.inputApk,
    els.shellApk,
    els.outputApk,
    els.ndkPath,
    els.protectionMap,
    els.reportJsonPath,
    els.releaseManifestPath,
    els.minExtract,
    els.minVmp,
    els.minDex2c,
    els.minScore,
    els.dex2cOllvmClang,
    els.keystorePath,
    els.ksPass,
    els.keyAlias,
    els.keyPass,
    els.signCertSha256,
  ].forEach((input) => {
    if (input) input.addEventListener("input", scheduleRenderCommand);
  });

  [
    ["featureExtract", els.featureExtract],
    ["featureVmpDex", els.featureVmpDex],
    ["featureDex2c", els.featureDex2c],
    ["featureVmpShellDex", els.featureVmpShellDex],
    ["featurePolymorphicShell", els.featurePolymorphicShell],
    ["featureAiDecoy", els.featureAiDecoy],
    ["extractOnDemand", els.extractOnDemand],
    ["autoProtectProfile", els.methodSmartPreset],
    ["vmpObfuscationPreset", els.vmpObfuscationPreset],
    ["vmpVmTier", els.vmpVmTier],
    ["dex2cOllvm", els.dex2cOllvm],
    ["dex2cOllvmRequired", els.dex2cOllvmRequired],
    ["commercialMode", els.commercialMode],
    ["flutterMode", els.flutterMode],
    ["signingEnabled", els.signingEnabled],
    ["perApkKey", els.perApkKey],
    ["detectRoot", els.detectRoot],
    ["detectEmulator", els.detectEmulator],
    ["protectDexPages", els.protectDexPages],
    ["blockProxyVpn", els.blockProxyVpn],
    ["releaseManifestEnabled", els.releaseManifestEnabled],
  ].forEach(([key, input]) => {
    if (!input) return;
    input.addEventListener("change", () => {
      if (key === "featureExtract") {
        state.features.extract = input.checked;
      } else if (key === "featureVmpDex") {
        state.features.vmpDex = input.checked;
      } else if (key === "featureDex2c") {
        state.features.dex2c = input.checked;
      } else if (key === "featureVmpShellDex") {
        state.features.vmpShellDex = input.checked;
      } else if (key === "featurePolymorphicShell") {
        state.features.polymorphicShell = input.checked;
      } else if (key === "featureAiDecoy") {
        state.features.aiDecoy = input.checked;
      } else if (key === "autoProtectProfile") {
        state.autoProtectProfile = input.value;
      } else if (key === "vmpObfuscationPreset") {
        state.vmpObfuscationPreset = input.value;
      } else if (key === "vmpVmTier") {
        state.vmpVmTier = input.value;
      } else {
        state[key] = input.checked;
      }

      if (key === "commercialMode" && input.checked && els.perApkKey && !els.perApkKey.checked) {
        els.perApkKey.checked = true;
        state.perApkKey = true;
      }
      if (key === "commercialMode" && input.checked && els.dex2cOllvm && !els.dex2cOllvm.checked) {
        els.dex2cOllvm.checked = true;
        state.dex2cOllvm = true;
      }
      if (key === "dex2cOllvm" && !input.checked && els.commercialMode.checked) {
        input.checked = true;
        state.dex2cOllvm = true;
        showToast("商业模式需要启用 DEX2C OLLVM", "warning");
      }
      if (key === "perApkKey" && !input.checked && els.commercialMode.checked) {
        input.checked = true;
        state.perApkKey = true;
        showToast("商业模式需要启用 Per-APK 密钥", "warning");
      }
      if (key === "flutterMode") {
        state.target = input.checked ? "flutter" : "android";
        syncGroup("[data-target]", state.target);
      }

      if (key === "commercialMode" || key === "signingEnabled") {
        normalizeScoreGate(collectConfig(), true);
      }

      scheduleRenderCommand();
    });
  });

  if (els.abiArm64) els.abiArm64.addEventListener("change", scheduleRenderCommand);
  if (els.abiArm32) els.abiArm32.addEventListener("change", scheduleRenderCommand);
  if (els.abiX86_64) els.abiX86_64.addEventListener("change", scheduleRenderCommand);
  if (els.abiX86) els.abiX86.addEventListener("change", scheduleRenderCommand);

  // Real-time inline validation: clear errors on interaction
  if (els.inputApk) els.inputApk.addEventListener("input", () => clearFieldError("apkDropZone"));
  [els.featureExtract, els.featureVmpDex, els.featureDex2c].forEach(cb => {
    if (cb) cb.addEventListener("change", () => clearFieldError("featureCardsSection"));
  });
  if (els.keystorePath) els.keystorePath.addEventListener("input", () => clearFieldError("keystorePath"));
  if (els.keyAlias) els.keyAlias.addEventListener("input", () => clearFieldError("keyAlias"));
  if (els.ksPass) els.ksPass.addEventListener("input", () => clearFieldError("ksPass"));
  if (els.signCertSha256) els.signCertSha256.addEventListener("input", () => clearFieldError("signCertSha256"));

  if (els.copyCommand) els.copyCommand.addEventListener("click", copyCommand);
  if (els.startHardening) els.startHardening.addEventListener("click", startHardening);
  if (els.reportFile) els.reportFile.addEventListener("change", handleReportUpload);
  if (els.loadSample) els.loadSample.addEventListener("click", () => renderReport(sampleReport));
}

function applyProfile(profile) {
  state.profile = profile;

  const common = {
    perApkKey: true,
    releaseManifestEnabled: false,
    commercialMode: false,
    signingEnabled: false,
    features: {
      extract: true,
      vmpDex: true,
      dex2c: true,
      vmpShellDex: false,
      polymorphicShell: false,
      aiDecoy: false,
    },
    extractOnDemand: true,
    autoProtectProfile: "balanced",
    vmpObfuscationPreset: "light",
    vmpVmTier: "auto",
    dex2cOllvm: true,
    dex2cOllvmRequired: false,
    dex2cOllvmClang: "",
    shellApk: "",
    outputApk: "",
    reportJsonPath: "",
    releaseManifestPath: "release/release_manifest.json",
  };

  const profiles = {
    flutter_prod: {
      ...common,
      target: "flutter",
      flutterMode: true,
      targetAbis: "arm64-v8a,armeabi-v7a",
      riskPolicy: "block",
      riskProfile: "strict",
      detectRoot: true,
      detectEmulator: true,
      protectDexPages: true,
      blockProxyVpn: true,
      extractOnDemand: true,
      autoProtectProfile: "balanced",
      vmpVmTier: "auto",
      minExtract: 120,
      minVmp: 30,
      minDex2c: 15,
      minScore: 80,
      protectionMap: "en/auto-protect-flutter.txt",
      outputApk: "",
    },
    android_prod: {
      ...common,
      target: "android",
      flutterMode: false,
      targetAbis: "arm64-v8a",
      riskPolicy: "block",
      riskProfile: "strict",
      detectRoot: true,
      detectEmulator: true,
      protectDexPages: true,
      blockProxyVpn: true,
      extractOnDemand: true,
      autoProtectProfile: "balanced",
      vmpVmTier: "auto",
      minExtract: 40,
      minVmp: 20,
      minDex2c: 5,
      minScore: 80,
      protectionMap: "auto-protect-demo.txt",
      outputApk: "",
    },
    lab_debug: {
      ...common,
      target: "android",
      flutterMode: false,
      targetAbis: "arm64-v8a",
      riskPolicy: "off",
      riskProfile: "compat",
      detectRoot: false,
      detectEmulator: false,
      protectDexPages: true,
      blockProxyVpn: false,
      extractOnDemand: false,
      autoProtectProfile: "compat",
      vmpVmTier: "compat",
      minExtract: 0,
      minVmp: 0,
      minDex2c: 0,
      minScore: 0,
      protectionMap: "auto-protect-demo.txt",
      outputApk: "",
    },
  };

  Object.assign(state, profiles[profile]);
  state.features = { ...profiles[profile].features };

  els.featureExtract.checked = state.features.extract;
  els.featureVmpDex.checked = state.features.vmpDex;
  els.featureDex2c.checked = state.features.dex2c;
  if (els.featureVmpShellDex) els.featureVmpShellDex.checked = state.features.vmpShellDex;
  if (els.featurePolymorphicShell) els.featurePolymorphicShell.checked = state.features.polymorphicShell;
  if (els.featureAiDecoy) els.featureAiDecoy.checked = state.features.aiDecoy;
  if (els.extractOnDemand) els.extractOnDemand.checked = state.extractOnDemand;
  if (els.methodSmartPreset) els.methodSmartPreset.value = state.autoProtectProfile;
  if (els.vmpObfuscationPreset) els.vmpObfuscationPreset.value = state.vmpObfuscationPreset;
  if (els.vmpVmTier) els.vmpVmTier.value = state.vmpVmTier;
  if (els.dex2cOllvm) els.dex2cOllvm.checked = state.dex2cOllvm;
  if (els.dex2cOllvmRequired) els.dex2cOllvmRequired.checked = state.dex2cOllvmRequired;
  if (els.dex2cOllvmClang) els.dex2cOllvmClang.value = state.dex2cOllvmClang;
  // Sync ABI checkboxes from profile
  const profileAbis = (state.targetAbis || "").split(",").map(s => s.trim());
  if (els.abiArm64) els.abiArm64.checked = profileAbis.includes("arm64-v8a");
  if (els.abiArm32) els.abiArm32.checked = profileAbis.includes("armeabi-v7a");
  if (els.abiX86_64) els.abiX86_64.checked = profileAbis.includes("x86_64");
  if (els.abiX86) els.abiX86.checked = profileAbis.includes("x86");
  els.flutterMode.checked = state.flutterMode;
  els.commercialMode.checked = state.commercialMode;
  els.signingEnabled.checked = state.signingEnabled;
  els.perApkKey.checked = state.perApkKey;
  els.detectRoot.checked = state.detectRoot;
  els.detectEmulator.checked = state.detectEmulator;
  if (els.protectDexPages) els.protectDexPages.checked = state.protectDexPages;
  els.blockProxyVpn.checked = state.blockProxyVpn;
  els.releaseManifestEnabled.checked = state.releaseManifestEnabled;
  if (els.releaseManifestPath) els.releaseManifestPath.value = state.releaseManifestPath || "release/release_manifest.json";
  els.protectionMap.value = state.protectionMap;
  els.shellApk.value = state.shellApk || state.defaultShellApk || "";
  els.outputApk.value = state.outputApk;
  els.reportJsonPath.value = state.reportJsonPath || "";
  els.minExtract.value = state.minExtract;
  els.minVmp.value = state.minVmp;
  els.minDex2c.value = state.minDex2c;
  els.minScore.value = state.minScore;
  normalizeScoreGate(collectConfig(), true);

  if (isPlaceholderNdk(els.ndkPath.value) && state.environment.ndk) {
    els.ndkPath.value = state.environment.ndk;
  }

  syncGroup("[data-profile]", state.profile);
  syncGroup("[data-target]", state.target);
  syncGroup("[data-policy]", state.riskPolicy);
  syncGroup("[data-risk]", state.riskProfile);
  renderCommand();
}

function applyQuickPreset(preset) {
  state.profile = "custom";
  const currentFlutter = els.flutterMode ? els.flutterMode.checked : state.flutterMode;
  const currentTarget = currentFlutter ? "flutter" : "android";

  const presets = {
    compat: {
      target: currentTarget,
      flutterMode: currentFlutter,
      riskPolicy: "warn",
      riskProfile: "compat",
      detectRoot: false,
      detectEmulator: false,
      protectDexPages: true,
      blockProxyVpn: false,
      commercialMode: false,
      signingEnabled: false,
      perApkKey: true,
      releaseManifestEnabled: false,
      extractOnDemand: false,
      autoProtectProfile: "compat",
      vmpObfuscationPreset: "light",
      vmpVmTier: "compat",
      dex2cOllvm: true,
      dex2cOllvmRequired: false,
      minExtract: currentFlutter ? 60 : 18,
      minVmp: currentFlutter ? 12 : 8,
      minDex2c: 0,
      minScore: 60,
      features: {
        extract: true,
        vmpDex: true,
        dex2c: false,
        vmpShellDex: false,
        polymorphicShell: true,
        aiDecoy: false,
      },
    },
    strong: {
      target: currentTarget,
      flutterMode: currentFlutter,
      riskPolicy: "block",
      riskProfile: "strict",
      detectRoot: true,
      detectEmulator: true,
      protectDexPages: true,
      blockProxyVpn: true,
      commercialMode: true,
      signingEnabled: false,
      perApkKey: true,
      releaseManifestEnabled: false,
      extractOnDemand: true,
      autoProtectProfile: "strong",
      vmpObfuscationPreset: "medium",
      vmpVmTier: "strong",
      dex2cOllvm: true,
      dex2cOllvmRequired: true,
      minExtract: currentFlutter ? 160 : 60,
      minVmp: currentFlutter ? 60 : 36,
      minDex2c: currentFlutter ? 12 : 8,
      minScore: 90,
      features: {
        extract: true,
        vmpDex: true,
        dex2c: true,
        vmpShellDex: true,
        polymorphicShell: true,
        aiDecoy: true,
      },
    },
  };

  const selected = presets[preset];
  if (!selected) return;
  Object.assign(state, selected);
  state.features = { ...selected.features };

  if (els.featureExtract) els.featureExtract.checked = state.features.extract;
  if (els.featureVmpDex) els.featureVmpDex.checked = state.features.vmpDex;
  if (els.featureDex2c) els.featureDex2c.checked = state.features.dex2c;
  if (els.featureVmpShellDex) els.featureVmpShellDex.checked = state.features.vmpShellDex;
  if (els.featurePolymorphicShell) els.featurePolymorphicShell.checked = state.features.polymorphicShell;
  if (els.featureAiDecoy) els.featureAiDecoy.checked = state.features.aiDecoy;
  if (els.extractOnDemand) els.extractOnDemand.checked = state.extractOnDemand;
  if (els.methodSmartPreset) els.methodSmartPreset.value = state.autoProtectProfile;
  if (els.vmpObfuscationPreset) els.vmpObfuscationPreset.value = state.vmpObfuscationPreset;
  if (els.vmpVmTier) els.vmpVmTier.value = state.vmpVmTier;
  if (els.dex2cOllvm) els.dex2cOllvm.checked = state.dex2cOllvm;
  if (els.dex2cOllvmRequired) els.dex2cOllvmRequired.checked = state.dex2cOllvmRequired;
  if (els.commercialMode) els.commercialMode.checked = state.commercialMode;
  if (els.signingEnabled) els.signingEnabled.checked = state.signingEnabled;
  if (els.perApkKey) els.perApkKey.checked = state.perApkKey;
  if (els.detectRoot) els.detectRoot.checked = state.detectRoot;
  if (els.detectEmulator) els.detectEmulator.checked = state.detectEmulator;
  if (els.protectDexPages) els.protectDexPages.checked = state.protectDexPages;
  if (els.blockProxyVpn) els.blockProxyVpn.checked = state.blockProxyVpn;
  if (els.releaseManifestEnabled) els.releaseManifestEnabled.checked = state.releaseManifestEnabled;
  if (els.minExtract) els.minExtract.value = state.minExtract;
  if (els.minVmp) els.minVmp.value = state.minVmp;
  if (els.minDex2c) els.minDex2c.value = state.minDex2c;
  if (els.minScore) els.minScore.value = state.minScore;

  document.querySelectorAll("[data-profile-card]").forEach(c => c.classList.remove("selected"));
  syncGroup("[data-policy]", state.riskPolicy);
  syncGroup("[data-risk]", state.riskProfile);
  normalizeScoreGate(collectConfig(), true);
  renderCommand();
  showToast(preset === "compat" ? "已应用兼容推荐模板" : "已应用强保护模板", "success");
}

function collectConfig() {
  const abis = [];
  if (els.abiArm64 && els.abiArm64.checked) abis.push("arm64-v8a");
  if (els.abiArm32 && els.abiArm32.checked) abis.push("armeabi-v7a");
  if (els.abiX86_64 && els.abiX86_64.checked) abis.push("x86_64");
  if (els.abiX86 && els.abiX86.checked) abis.push("x86");
  return normalizeScoreGate({
    inputApk: els.inputApk.value.trim(),
    shellApk: els.shellApk.value.trim(),
    outputApk: els.outputApk.value.trim(),
    ndkPath: resolveNdkPath(els.ndkPath.value.trim()),
    protectionMap: els.protectionMap.value.trim(),
    reportJsonPath: els.reportJsonPath.value.trim(),
    releaseManifestPath: els.releaseManifestPath ? els.releaseManifestPath.value.trim() : "",
    keystorePath: els.keystorePath.value.trim(),
    ksPass: els.ksPass.value,
    keyAlias: els.keyAlias.value.trim(),
    keyPass: els.keyPass.value,
    signCertSha256: els.signCertSha256 ? els.signCertSha256.value.trim() : "",
    riskPolicy: state.riskPolicy,
    riskProfile: state.riskProfile,
    commercialMode: els.commercialMode.checked,
    flutterMode: els.flutterMode.checked,
    signingEnabled: els.signingEnabled.checked,
    perApkKey: els.perApkKey.checked,
    detectRoot: els.detectRoot.checked,
    detectEmulator: els.detectEmulator.checked,
    protectDexPages: els.protectDexPages ? els.protectDexPages.checked : true,
    blockProxyVpn: els.blockProxyVpn.checked,
    releaseManifestEnabled: els.releaseManifestEnabled.checked,
    minExtract: asNumber(els.minExtract.value),
    minVmp: asNumber(els.minVmp.value),
    minDex2c: asNumber(els.minDex2c.value),
    minScore: asNumber(els.minScore.value),
    featureExtract: els.featureExtract.checked,
    featureVmpDex: els.featureVmpDex.checked,
    featureDex2c: els.featureDex2c.checked,
    featureVmpShellDex: els.featureVmpShellDex ? els.featureVmpShellDex.checked : false,
    featurePolymorphicShell: els.featurePolymorphicShell ? els.featurePolymorphicShell.checked : false,
    featureAiDecoy: els.featureAiDecoy ? els.featureAiDecoy.checked : false,
    extractOnDemand: els.extractOnDemand ? els.extractOnDemand.checked : state.riskProfile !== "compat",
    autoProtectProfile: els.methodSmartPreset ? els.methodSmartPreset.value : "balanced",
    vmpObfuscationPreset: els.vmpObfuscationPreset ? els.vmpObfuscationPreset.value : "light",
    vmpVmTier: els.vmpVmTier ? els.vmpVmTier.value : "auto",
    dex2cOllvm: els.dex2cOllvm ? els.dex2cOllvm.checked : true,
    dex2cOllvmRequired: els.dex2cOllvmRequired ? els.dex2cOllvmRequired.checked : false,
    dex2cOllvmClang: els.dex2cOllvmClang ? els.dex2cOllvmClang.value.trim() : "",
    targetAbis: abis.join(","),
  });
}

// ---------------------------------------------------------------------------
// Debounced command preview
// ---------------------------------------------------------------------------
let _renderCommandTimer = null;
function scheduleRenderCommand() {
  if (_renderCommandTimer) clearTimeout(_renderCommandTimer);
  _renderCommandTimer = setTimeout(renderCommand, 200);
}

function renderCommand() {
  const config = collectConfig();

  state.flutterMode = config.flutterMode;
  state.commercialMode = config.commercialMode;
  state.signingEnabled = config.signingEnabled;
  state.signCertSha256 = config.signCertSha256;
  state.perApkKey = config.perApkKey;
  state.detectRoot = config.detectRoot;
  state.detectEmulator = config.detectEmulator;
  state.protectDexPages = config.protectDexPages;
  state.blockProxyVpn = config.blockProxyVpn;
  state.releaseManifestEnabled = config.releaseManifestEnabled;
  state.releaseManifestPath = config.releaseManifestPath || "release/release_manifest.json";
  state.extractOnDemand = config.extractOnDemand;
  state.autoProtectProfile = config.autoProtectProfile;
  state.vmpObfuscationPreset = config.vmpObfuscationPreset;
  state.vmpVmTier = config.vmpVmTier;
  state.dex2cOllvm = config.dex2cOllvm;
  state.dex2cOllvmRequired = config.dex2cOllvmRequired;
  state.dex2cOllvmClang = config.dex2cOllvmClang;
  state.features.extract = config.featureExtract;
  state.features.vmpDex = config.featureVmpDex;
  state.features.dex2c = config.featureDex2c;
  state.features.vmpShellDex = config.featureVmpShellDex;
  state.features.polymorphicShell = config.featurePolymorphicShell;
  state.features.aiDecoy = config.featureAiDecoy;

  updateConditionalSections(config);

  const lines = [];
  lines.push("python d:\\Engineering\\projects\\enko\\packer\\harden_apk.py `");
  lines.push(`  --input-apk "${config.inputApk}" \``);
  lines.push(`  --shell-apk "${config.shellApk}" \``);
  lines.push(`  --output-apk "${config.outputApk}" \``);
  lines.push(`  --risk-policy ${config.riskPolicy} \``);
  lines.push(`  --risk-profile ${config.riskProfile} \``);
  lines.push(config.blockProxyVpn ? "  --block-proxy-vpn `" : "  --allow-proxy-vpn `");
  lines.push(config.detectRoot ? "  --detect-root `" : "  --disable-root-check `");
  lines.push(config.detectEmulator ? "  --detect-emulator `" : "  --disable-emulator-check `");
  lines.push(config.protectDexPages ? "  --protect-dex-pages `" : "  --no-protect-dex-pages `");
  lines.push(config.extractOnDemand ? "  --extract-on-demand `" : "  --extract-bulk-restore `");
  lines.push(`  --auto-protect-profile ${config.autoProtectProfile} \``);
  lines.push(config.perApkKey ? "  --per-apk-key `" : "  --no-per-apk-key `");

  if (config.flutterMode) {
    lines.push("  --flutter-mode `");
  }
  if (config.commercialMode) {
    lines.push("  --commercial-mode `");
  }
  if (config.protectionMap) {
    lines.push(`  --protection-map "${config.protectionMap}" \``);
  }
  if (config.featureVmpDex || config.featureVmpShellDex) {
    lines.push(`  --vmp-dex-obfuscation-preset ${config.vmpObfuscationPreset} \``);
    lines.push(`  --vmp-vm-tier ${config.vmpVmTier} \``);
  }

  const resolvedNdk = resolveNdkPath(config.ndkPath);
  if (resolvedNdk) {
    lines.push(`  --ndk-path "${resolvedNdk}" \``);
  }

  if (config.featureExtract && config.minExtract > 0) {
    lines.push(`  --min-extract-count ${config.minExtract} \``);
  }
  if (config.featureVmpDex && config.minVmp > 0) {
    lines.push(`  --min-vmp-dex-count ${config.minVmp} \``);
  }
  if (config.featureDex2c && config.minDex2c > 0) {
    lines.push(`  --min-dex2c-count ${config.minDex2c} \``);
  }
  if (config.minScore > 0) {
    lines.push(`  --min-security-score ${config.minScore} \``);
  }
  if (config.reportJsonPath) {
    lines.push(`  --report-json "${config.reportJsonPath}" \``);
  }
  if (config.releaseManifestEnabled) {
    const manifestPath = config.releaseManifestPath || "release/release_manifest.json";
    lines.push(`  --release-manifest "${manifestPath}" \``);
  }
  if (config.featureVmpShellDex) {
    lines.push("  --vmp-shell-dex `");
  }
  // AI decoy (P5-7) — only emit when not already auto-on under commercial mode
  if (config.featureAiDecoy && !config.commercialMode) {
    lines.push("  --ai-decoy `");
  }
  if (config.featurePolymorphicShell) {
    lines.push("  --polymorphic-shell `");
  }
  if (config.featureDex2c) {
    lines.push(config.dex2cOllvm ? "  --dex2c-ollvm `" : "  --no-dex2c-ollvm `");
    if (config.dex2cOllvm && config.dex2cOllvmClang) {
      lines.push(`  --dex2c-ollvm-clang "${config.dex2cOllvmClang}" \``);
    }
    if (config.dex2cOllvm && config.dex2cOllvmRequired) {
      lines.push("  --dex2c-ollvm-required `");
    }
  }

  if (config.signCertSha256) {
    lines.push(`  --sign-cert-sha256 "${config.signCertSha256}" \``);
  }

  if (config.targetAbis) {
    lines.push(`  --target-abis "${config.targetAbis}" \``);
  }

  if (config.signingEnabled) {
    lines.push(`  --keystore "${config.keystorePath}" \``);
    lines.push(`  --ks-pass "***" \``);
    lines.push(`  --key-alias "${config.keyAlias}" \``);
    lines.push(`  --key-pass "***" \``);
  } else {
    lines.push("  --skip-sign `");
  }

  if (state.environment.apktool) {
    lines.push(`  --apktool "${state.environment.apktool}" \``);
  }
  if (state.environment.zipalign) {
    lines.push(`  --zipalign "${state.environment.zipalign}" \``);
  }
  if (state.environment.apksigner) {
    lines.push(`  --apksigner "${state.environment.apksigner}"`);
  } else {
    stripTrailingBacktick(lines);
  }

  const disabledPhases = [];
  if (!config.featureExtract) {
    disabledPhases.push("extract");
  }
  if (!config.featureVmpDex) {
    disabledPhases.push("vmp_dex");
  }
  if (!config.featureDex2c) {
    disabledPhases.push("dex2c");
  }
  if (disabledPhases.length) {
    lines.push("");
    lines.push(`# local web console will filter protection-map phases: disable ${disabledPhases.join(", ")}`);
  }

  els.commandPreview.textContent = lines.join("\n");
}

function updateConditionalSections(config = collectConfig()) {
  if (els.signingBox) {
    els.signingBox.style.display = config.signingEnabled ? "block" : "none";
  }
  if (els.externalSigningBox) {
    els.externalSigningBox.style.display = "block";
  }
  if (els.releaseManifestBox) {
    els.releaseManifestBox.style.display = config.releaseManifestEnabled ? "block" : "none";
  }
  els.profileBadge.textContent = profileNames[state.profile];
  els.heroMode.textContent = config.flutterMode ? "Flutter" : "Android";
  els.heroPolicy.textContent = `${config.riskPolicy} / ${config.riskProfile}`;
  els.heroGateCount.textContent = config.flutterMode ? "6 + native-core" : "6";

  // Dynamic summary panel
  const summaryAbis = document.getElementById("summaryAbis");
  const summaryFeatures = document.getElementById("summaryFeatures");
  const summaryPolicy = document.getElementById("summaryPolicy");
  const abiSummary = document.getElementById("abiSummary");
  const capabilityMatrix = document.getElementById("capabilityMatrix");

  if (summaryAbis) {
    const abis = [];
    if (els.abiArm64 && els.abiArm64.checked) abis.push("ARM64");
    if (els.abiArm32 && els.abiArm32.checked) abis.push("ARMv7");
    if (els.abiX86_64 && els.abiX86_64.checked) abis.push("x86_64");
    if (els.abiX86 && els.abiX86.checked) abis.push("x86");
    summaryAbis.textContent = abis.length ? abis.join(" · ") : "未选择";
    if (abiSummary) abiSummary.textContent = abis.length ? `已选 ${abis.length} 个平台` : "未选择平台";
  }
  if (summaryFeatures) {
    const feats = [];
    if (config.featureExtract) feats.push("Extract");
    if (config.featureVmpDex) feats.push("VMP");
    if (config.featureDex2c) feats.push("DEX2C");
    if (config.featureExtract && config.extractOnDemand) feats.push("按需抽取");
    feats.push(`智能 ${config.autoProtectProfile}`);
    if ((config.featureVmpDex || config.featureVmpShellDex) && config.vmpObfuscationPreset !== "stable") feats.push(`VMP ${config.vmpObfuscationPreset}`);
    if (config.featureDex2c && config.dex2cOllvm) feats.push("OLLVM");
    if (config.signingEnabled) feats.push("加固端签名");
    else feats.push("待原证书签名");
    if (config.protectDexPages) feats.push("DEX 页封存");
    if (config.commercialMode) feats.push("商业模式");
    if (config.releaseManifestEnabled) feats.push("Release Manifest");
    summaryFeatures.textContent = feats.length ? feats.join(" · ") : "无";
  }
  if (summaryPolicy) {
    // P6-1: graded response. Default block+balanced/compat caps at RESTRICT,
    // never kills the process. Only strict+block or commercial-mode terminates.
    const policyMap = { block: "阻断", degrade: "降级运行", warn: "提示用户", log: "静默上报", off: "关闭检测" };
    const profileMap = { strict: "严格", balanced: "均衡", compat: "兼容" };
    const policyLabel = policyMap[config.riskPolicy] || config.riskPolicy;
    const profileLabel = profileMap[config.riskProfile] || config.riskProfile;
    const canTerminate = config.commercialMode || config.riskProfile === "strict";
    const tag = config.riskPolicy === "off"
      ? ""
      : (canTerminate
          ? " · 可终止进程"
          : " · 不杀进程（限制+记录）");
    summaryPolicy.textContent = `${policyLabel} / ${profileLabel}${tag}`;
    summaryPolicy.className = canTerminate
      ? "text-amber-400 font-medium"
      : "text-on-surface font-medium";
  }
  if (capabilityMatrix) {
    renderCapabilityMatrix(capabilityMatrix, config);
  }
}

function renderCapabilityMatrix(container, config) {
  // P6-1: surface the actual graded-response outcome of the current policy mix
  // so users see whether their config can kill real users.
  const canTerminate = config.commercialMode || config.riskProfile === "strict";
  const offPolicy = config.riskPolicy === "off";
  const riskResponseValue = offPolicy
    ? "关闭"
    : (canTerminate ? "可终止（高风险）" : "记录+限制（不杀进程）");

  const items = [
    {
      title: "方法抽取",
      value: config.featureExtract ? (config.extractOnDemand ? "按需恢复" : "批量恢复") : "关闭",
      enabled: config.featureExtract,
    },
    {
      title: "VMP DEX",
      value: config.featureVmpDex ? `开启 · ${config.vmpObfuscationPreset} · ${config.vmpVmTier}` : "关闭",
      enabled: config.featureVmpDex,
    },
    {
      title: "VM 档位",
      value: (config.featureVmpDex || config.featureVmpShellDex) ? config.vmpVmTier : "未使用",
      enabled: Boolean(config.featureVmpDex || config.featureVmpShellDex),
    },
    {
      title: "壳自保护",
      value: config.featureVmpShellDex ? "Shell VMP" : "关闭",
      enabled: config.featureVmpShellDex,
    },
    {
      title: "DEX2C",
      value: config.featureDex2c ? (config.dex2cOllvm ? `OLLVM ${config.dex2cOllvmRequired ? "required" : "best-effort"}` : "NDK clang") : "关闭",
      enabled: config.featureDex2c,
    },
    {
      title: "多态壳",
      value: config.featurePolymorphicShell ? "类/方法/字段" : "关闭",
      enabled: config.featurePolymorphicShell,
    },
    {
      title: "AI 诱饵",
      value: (config.featureAiDecoy || config.commercialMode)
        ? (config.commercialMode ? "canary（商业自动）" : "canary 已开")
        : "关闭",
      enabled: Boolean(config.featureAiDecoy || config.commercialMode),
    },
    {
      title: "DEX 页封存",
      value: config.protectDexPages ? "开启" : "关闭",
      enabled: config.protectDexPages,
    },
    {
      title: "风险响应",
      value: riskResponseValue,
      enabled: !offPolicy,
      partial: !offPolicy && !canTerminate,
    },
    {
      title: "签名策略",
      value: config.signingEnabled ? "加固端同证书签名" : "外部同证书重签",
      enabled: Boolean(config.signingEnabled || config.signCertSha256),
      partial: !config.signingEnabled,
    },
    {
      title: "发布门禁",
      value: [
        config.commercialMode ? "商业" : "",
        config.releaseManifestEnabled ? "Manifest" : "",
        config.perApkKey ? "Per-APK key" : "",
      ].filter(Boolean).join(" · ") || "基础模式",
      enabled: Boolean(config.commercialMode || config.releaseManifestEnabled || config.perApkKey),
    },
  ];

  container.innerHTML = items.map((item) => {
    const cls = item.enabled
      ? (item.partial ? "text-yellow-400" : "text-secondary")
      : "text-slate-500";
    const icon = item.enabled ? (item.partial ? "radio_button_partial" : "check_circle") : "radio_button_unchecked";
    return `<div class="min-w-0 flex items-center gap-2 text-[11px]">
      <span class="material-symbols-outlined ${cls}" style="font-size:15px">${icon}</span>
      <span class="text-slate-500 shrink-0">${escapeHtml(item.title)}</span>
      <span class="text-on-surface truncate">${escapeHtml(item.value)}</span>
    </div>`;
  }).join("");
}

function syncGroup(selector, value) {
  document.querySelectorAll(selector).forEach((button) => {
    const matched =
      button.dataset.profile === value ||
      button.dataset.target === value ||
      button.dataset.policy === value ||
      button.dataset.risk === value;
    button.classList.toggle("active", matched);
    if (button.matches('input[type="radio"], input[type="checkbox"]')) {
      button.checked = matched;
    }
    if (button.classList.contains("action")) {
      button.classList.toggle("primary", matched && button.dataset.profile === value);
    }
  });
}

async function copyCommand() {
  await navigator.clipboard.writeText(els.commandPreview.textContent);
  const oldText = els.copyCommand.textContent;
  els.copyCommand.textContent = "已复制";
  setTimeout(() => {
    els.copyCommand.textContent = oldText;
  }, 1400);
}

// APK file upload handler
const MAX_APK_SIZE_MB = 512;
async function uploadApkFile(file) {
  const dropZone = document.getElementById("apkDropZone");
  const prompt = document.getElementById("apkUploadPrompt");
  const statusEl = document.getElementById("apkUploadStatus");
  const uploading = document.getElementById("apkUploading");
  const nameEl = document.getElementById("apkFileName");
  const sizeEl = document.getElementById("apkFileSize");
  const uploadBar = document.getElementById("apkUploadBar");
  const uploadPercent = document.getElementById("apkUploadPercent");
  const uploadLabel = document.getElementById("apkUploadLabel");

  if (!file || !file.name.endsWith(".apk")) {
    showToast("请选择 .apk 文件", "warning");
    return;
  }

  const sizeMB = file.size / 1024 / 1024;
  if (sizeMB > MAX_APK_SIZE_MB) {
    showToast(`文件过大 (${sizeMB.toFixed(0)} MB)，最大支持 ${MAX_APK_SIZE_MB} MB`, "error");
    return;
  }
  if (sizeMB > 200) {
    showToast(`文件较大 (${sizeMB.toFixed(0)} MB)，上传可能需要较长时间`, "warning");
  }

  // Show uploading state with progress bar
  if (prompt) prompt.classList.add("hidden");
  if (statusEl) statusEl.classList.add("hidden");
  if (uploading) uploading.classList.remove("hidden");
  if (uploadBar) uploadBar.style.width = "0%";
  if (uploadPercent) uploadPercent.textContent = "0%";
  if (uploadLabel) uploadLabel.textContent = "正在上传...";

  try {
    const result = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");
      const token = localStorage.getItem("enko_token");
      if (token) xhr.setRequestHeader("Authorization", "Bearer " + token);

      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          if (uploadBar) uploadBar.style.width = pct + "%";
          if (uploadPercent) uploadPercent.textContent = pct + "%";
          if (uploadLabel) uploadLabel.textContent = pct < 100 ? "正在上传..." : "服务器处理中...";
        }
      });

      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject(new Error(data.error || data.detail || `上传失败 (${xhr.status})`));
        } catch { reject(new Error("服务器响应异常")); }
      };
      xhr.onerror = () => reject(new Error("网络连接失败，请检查网络"));
      xhr.ontimeout = () => reject(new Error("上传超时，请检查网络或减小文件"));
      xhr.timeout = 600000; // 10 min

      const formData = new FormData();
      formData.append("file", file);
      xhr.send(formData);
    });

    // Set the hidden inputApk field with server-side path
    els.inputApk.value = result.path;
    renderCommand();
    // Enable method analysis button
    const analyzeBtn = document.getElementById("analyzeMethodsBtn");
    if (analyzeBtn) analyzeBtn.disabled = false;

    // Show success
    if (uploading) uploading.classList.add("hidden");
    if (statusEl) statusEl.classList.remove("hidden");
    if (nameEl) nameEl.textContent = result.filename;
    if (sizeEl) sizeEl.textContent = `${(result.size / 1024 / 1024).toFixed(1)} MB`;
    if (dropZone) dropZone.classList.add("border-secondary/40");
    if (typeof runMethodAnalysis === "function" && analyzeBtn && !analyzeBtn.disabled) {
      showToast("上传完成，开始自动方法分析", "info");
      await runMethodAnalysis({ autoSaveRecommended: true, quiet: true });
    }
  } catch (error) {
    if (uploading) uploading.classList.add("hidden");
    if (prompt) prompt.classList.remove("hidden");
    showToast("上传失败: " + error.message, "error");
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  if (!sidebar) return;
  const isOpen = !sidebar.classList.contains("-translate-x-full");
  if (isOpen) {
    sidebar.classList.add("-translate-x-full");
    sidebar.classList.remove("translate-x-0");
    if (overlay) overlay.classList.add("hidden");
  } else {
    sidebar.classList.remove("-translate-x-full");
    sidebar.classList.add("translate-x-0");
    if (overlay) overlay.classList.remove("hidden");
  }
}
window.toggleSidebar = toggleSidebar;

function navigateTo(name, options = {}) {
  const viewSections = document.querySelectorAll(".view-section");
  const navLinks = document.querySelectorAll("[data-nav]");
  const topbarIcon = document.getElementById("topbar-icon");
  const topbarTitle = document.getElementById("topbar-title");

  const viewMeta = {
    dashboard:  { icon: "terminal", title: "控制面板" },
    "new-job":  { icon: "security", title: "新建任务" },
    jobs:       { icon: "list_alt", title: "任务列表" },
    "job-detail": { icon: "task_alt", title: "任务详情" },
    reports:    { icon: "analytics", title: "报告分析" },
    profiles:   { icon: "account_circle", title: "配置方案" },
    admin:      { icon: "admin_panel_settings", title: "用户管理" },
  };

  viewSections.forEach(s => s.classList.toggle("active", s.id === "view-" + name));
  navLinks.forEach(a => a.classList.toggle("active", a.dataset.nav === name));

  const meta = viewMeta[name];
  if (meta) {
    if (topbarIcon) topbarIcon.textContent = meta.icon;
    if (topbarTitle) topbarTitle.textContent = meta.title;
  }

  const shouldLoadData = options.load !== false && Boolean(auth.token);
  if (shouldLoadData && name === "dashboard") { loadDashboardStats(); loadEngineStatus(); }
  if (shouldLoadData && name === "jobs") loadJobsPage();
  if (shouldLoadData && name === "job-detail" && state.activeJobId) pollJob();
  if (shouldLoadData && name === "admin" && typeof adminLoadUsers === "function") adminLoadUsers();

  // Close mobile sidebar after navigation
  const sidebar = document.getElementById("sidebar");
  if (sidebar && !sidebar.classList.contains("-translate-x-full") && window.innerWidth < 768) {
    toggleSidebar();
  }
}
window.navigateTo = navigateTo;

document.addEventListener("click", (event) => {
  const navLink = event.target.closest?.("[data-nav]");
  if (!navLink) return;
  event.preventDefault();
  navigateTo(navLink.dataset.nav);
});

function initShellNavigation() {
  const navLinks = document.querySelectorAll("[data-nav]");
  navLinks.forEach(link => {
    if (link.dataset.navWired === "1") return;
    link.dataset.navWired = "1";
    link.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      navigateTo(link.dataset.nav);
    });
    link.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      navigateTo(link.dataset.nav);
    });
  });

  const menuToggle = document.getElementById("menuToggle");
  if (menuToggle && menuToggle.dataset.menuWired !== "1" && !menuToggle.hasAttribute("onclick")) {
    menuToggle.dataset.menuWired = "1";
    menuToggle.addEventListener("click", toggleSidebar);
  }

  const activeView = document.querySelector(".view-section.active");
  const activeName = activeView && activeView.id.startsWith("view-")
    ? activeView.id.slice(5)
    : "dashboard";
  navigateTo(activeName, { load: false });
}

function initNavigation() {
  initShellNavigation();

  // Profile card selection → sync to app.js applyProfile
  const profileCards = document.querySelectorAll("[data-profile-card]");
  function selectProfileCard(value) {
    profileCards.forEach(c => c.classList.toggle("selected", c.dataset.profileCard === value));
    if (typeof applyProfile === "function") applyProfile(value);
  }
  profileCards.forEach(card => {
    if (card.dataset.profileWired === "1") return;
    card.dataset.profileWired = "1";
    card.addEventListener("click", () => selectProfileCard(card.dataset.profileCard));
  });
  if (profileCards.length) selectProfileCard(profileCards[0].dataset.profileCard);

  document.querySelectorAll("[data-quick-preset]").forEach(btn => {
    if (btn.dataset.quickPresetWired === "1") return;
    btn.dataset.quickPresetWired = "1";
    btn.addEventListener("click", () => {
      if (typeof applyQuickPreset === "function") applyQuickPreset(btn.dataset.quickPreset);
    });
  });

  // Strategy radio buttons → sync to app.js state
  document.querySelectorAll('input[name="strategy"][data-policy]').forEach(radio => {
    if (radio.dataset.strategyWired === "1") return;
    radio.dataset.strategyWired = "1";
    radio.addEventListener("change", () => {
      if (radio.checked && typeof state !== "undefined") {
        state.riskPolicy = radio.value;
        if (typeof renderCommand === "function") renderCommand();
      }
    });
  });

  // Profile "copy and edit" buttons → apply profile + jump to new-job
  document.querySelectorAll(".profile-apply-btn[data-profile]").forEach(btn => {
    if (btn.dataset.profileApplyWired === "1") return;
    btn.dataset.profileApplyWired = "1";
    btn.addEventListener("click", () => {
      const profile = btn.dataset.profile;
      selectProfileCard(profile);
      navigateTo("new-job");
    });
  });

  // "Create custom plan" button → jump to new-job
  const createBtn = document.querySelector("#view-profiles button:has(span.material-symbols-outlined)");
  if (createBtn && createBtn.dataset.createProfileWired !== "1" && createBtn.textContent.includes("创建自定义方案")) {
    createBtn.dataset.createProfileWired = "1";
    createBtn.addEventListener("click", () => navigateTo("new-job"));
  }
}

function initUploadZone() {
  const fileInput = document.getElementById("apkFileInput");
  const dropZone = document.getElementById("apkDropZone");
  const reupload = document.getElementById("apkReupload");

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        uploadApkFile(fileInput.files[0]);
      }
    });
  }

  if (dropZone) {
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("border-primary", "bg-primary/10");
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("border-primary", "bg-primary/10");
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("border-primary", "bg-primary/10");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        uploadApkFile(e.dataTransfer.files[0]);
      }
    });
  }

  if (reupload) {
    reupload.addEventListener("click", (e) => {
      e.stopPropagation();
      const prompt = document.getElementById("apkUploadPrompt");
      const statusEl = document.getElementById("apkUploadStatus");
      if (statusEl) statusEl.classList.add("hidden");
      if (prompt) prompt.classList.remove("hidden");
      els.inputApk.value = "";
      if (els.protectionMap) els.protectionMap.value = "";
      if (fileInput) fileInput.value = "";
      const dz = document.getElementById("apkDropZone");
      if (dz) dz.classList.remove("border-secondary/40");
      renderCommand();
    });
  }
}

function validateForm() {
  const errors = [];
  const config = collectConfig();

  // Clear previous errors
  ["apkDropZone", "featureCardsSection", "keystorePath", "keyAlias", "ksPass", "signCertSha256"].forEach(clearFieldError);

  if (!config.inputApk) {
    errors.push("请先上传要加固的 APK 文件");
    showFieldError("apkDropZone", "请先上传要加固的 APK 文件");
  }
  if (!config.featureExtract && !config.featureVmpDex && !config.featureDex2c) {
    errors.push("至少选择一种保护功能");
    showFieldError("featureCardsSection", "至少选择一种保护功能");
  }
  if (config.signingEnabled) {
    if (!config.keystorePath) {
      errors.push("已启用签名但未填写 Keystore 路径");
      showFieldError("keystorePath", "请填写 Keystore 路径");
    }
    if (!config.keyAlias) {
      errors.push("已启用签名但未填写 Key Alias");
      showFieldError("keyAlias", "请填写 Key Alias");
    }
    if (!config.ksPass) {
      errors.push("已启用签名但未填写 Keystore 密码");
      showFieldError("ksPass", "请填写 Keystore 密码");
    }
  }
  if (config.signCertSha256) {
    const normalizedCert = config.signCertSha256.replace(/[:-]/g, "");
    if (!/^[0-9a-fA-F:-]+$/.test(config.signCertSha256) || normalizedCert.length !== 64) {
      errors.push("签名证书 SHA-256 必须是 64 位十六进制");
      showFieldError("signCertSha256", "请填写 64 位 SHA-256，可带冒号");
    }
  }
  return { valid: errors.length === 0, errors };
}

async function startHardening() {
  const validation = validateForm();
  if (!validation.valid) {
    showToast(validation.errors[0], "warning");
    return;
  }

  const config = collectConfig();

  els.startHardening.disabled = true;
  els.startHardening.textContent = "提交中...";

  // Hide download area
  const dlArea = document.getElementById("jobDownloadArea");
  if (dlArea) dlArea.classList.add("hidden");

  try {
    const response = await authFetch("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(parseApiError(payload) || "启动任务失败");
    }
    const payload = await response.json();

    state.activeJobId = payload.job.id;
    localStorage.setItem("enko_active_job", payload.job.id);
    navigateTo("job-detail");
    renderJob(payload.job);
    connectJobWebSocket(payload.job.id);
    startPolling();
    loadDashboardStats();
    loadJobsPage();
    showToast("任务已提交，后台开始加固", "success");
  } catch (error) {
    state.activeJobId = null;
    localStorage.removeItem("enko_active_job");
    navigateTo("job-detail");
    renderJob({
      status: "failed",
      error: error.message,
      log: [`[web-console] ${error.message}`],
    });
  } finally {
    els.startHardening.disabled = false;
    els.startHardening.textContent = "开始加固";
  }
}

function resolveNdkPath(configValue) {
  if (configValue && !isPlaceholderNdk(configValue)) {
    return configValue;
  }
  return state.environment.ndk || "";
}

function isPlaceholderNdk(value) {
  const lowered = String(value || "").trim().toLowerCase();
  return !lowered || lowered.includes("your-version") || lowered.includes("auto-detect");
}

function stripTrailingBacktick(lines) {
  if (!lines.length) {
    return;
  }
  const last = lines[lines.length - 1];
  if (last.endsWith(" `")) {
    lines[lines.length - 1] = last.slice(0, -2);
  }
}

// ---------------------------------------------------------------------------
// Admin Panel — user management (admin only)
// ---------------------------------------------------------------------------
function initAdminPanel() {
  // Show admin nav link only for admin user
  const navAdmin = document.getElementById("nav-admin");
  if (navAdmin && auth.username === "admin") {
    navAdmin.classList.remove("hidden");
  }

  const createBtn = document.getElementById("admin-create-btn");
  const refreshBtn = document.getElementById("admin-refresh-btn");
  if (createBtn) createBtn.addEventListener("click", adminCreateUser);
  if (refreshBtn) refreshBtn.addEventListener("click", adminLoadUsers);
}

async function adminLoadUsers() {
  const container = document.getElementById("admin-users-list");
  if (!container) return;
  container.innerHTML = '<p class="text-sm text-on-surface-variant">加载中...</p>';
  try {
    const resp = await authFetch("/api/admin/users");
    if (!resp.ok) { container.innerHTML = '<p class="text-sm text-error">加载失败</p>'; return; }
    const data = await resp.json();
    if (!data.users || data.users.length === 0) {
      container.innerHTML = '<p class="text-sm text-on-surface-variant">暂无用户</p>';
      return;
    }
    container.innerHTML = data.users.map(u => {
      const tierBadge = u.tier === "pro"
        ? '<span class="px-2 py-0.5 text-xs font-bold rounded-full bg-amber-500/20 text-amber-400">PRO</span>'
        : '<span class="px-2 py-0.5 text-xs font-bold rounded-full bg-surface-container text-on-surface-variant">FREE</span>';
      const isAdmin = u.username === "admin";
      const actions = isAdmin ? '<span class="text-xs text-on-surface-variant">管理员</span>' : `
        <select data-user="${u.username}" class="tier-select bg-surface-container-low rounded px-2 py-1 text-xs border border-outline-variant/20">
          <option value="free" ${u.tier === "free" ? "selected" : ""}>Free</option>
          <option value="pro" ${u.tier === "pro" ? "selected" : ""}>Pro</option>
        </select>
        <button data-delete-user="${u.username}" class="text-xs text-error hover:text-error/80 ml-2" title="删除用户">
          <span class="material-symbols-outlined" style="font-size:16px">delete</span>
        </button>`;
      const created = u.created_at ? new Date(u.created_at).toLocaleDateString("zh-CN") : "-";
      return `<div class="flex items-center justify-between p-3 rounded-xl bg-surface-container/50 border border-outline-variant/10">
        <div class="flex items-center gap-3">
          <span class="material-symbols-outlined text-on-surface-variant" style="font-size:20px">person</span>
          <span class="text-sm font-medium text-on-surface">${u.username}</span>
          ${tierBadge}
        </div>
        <div class="flex items-center gap-2">
          <span class="text-xs text-on-surface-variant">${created}</span>
          ${actions}
        </div>
      </div>`;
    }).join("");

    // Bind tier change events
    container.querySelectorAll(".tier-select").forEach(sel => {
      sel.addEventListener("change", async (e) => {
        const username = e.target.getAttribute("data-user");
        const newTier = e.target.value;
        try {
          const resp = await authFetch("/api/admin/set-tier", {
            method: "POST",
            body: JSON.stringify({ username, tier: newTier }),
          });
          if (resp.ok) {
            showToast(`已将 ${username} 设为 ${newTier === "pro" ? "专业版" : "免费版"}`, "success");
          } else {
            const err = await resp.json();
            showToast(parseApiError(err), "error");
            adminLoadUsers();
          }
        } catch (err) { showToast("操作失败: " + err.message, "error"); }
      });
    });

    // Bind delete events
    container.querySelectorAll("[data-delete-user]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const username = btn.getAttribute("data-delete-user");
        if (!confirm(`确定删除用户 ${username}？此操作不可撤回。`)) return;
        try {
          const resp = await authFetch(`/api/admin/users/${username}`, { method: "DELETE" });
          if (resp.ok) {
            showToast(`已删除用户 ${username}`, "success");
            adminLoadUsers();
          } else {
            const err = await resp.json();
            showToast(parseApiError(err), "error");
          }
        } catch (err) { showToast("删除失败: " + err.message, "error"); }
      });
    });
  } catch (err) {
    container.innerHTML = `<p class="text-sm text-error">${err.message}</p>`;
  }
}

async function adminCreateUser() {
  const usernameEl = document.getElementById("admin-new-username");
  const passwordEl = document.getElementById("admin-new-password");
  const tierEl = document.getElementById("admin-new-tier");
  const btn = document.getElementById("admin-create-btn");
  if (!usernameEl.value.trim() || !passwordEl.value) {
    showToast("请填写用户名和密码", "warning");
    return;
  }
  btn.disabled = true;
  btn.textContent = "创建中...";
  try {
    const resp = await authFetch("/api/admin/create-user", {
      method: "POST",
      body: JSON.stringify({
        username: usernameEl.value.trim(),
        password: passwordEl.value,
        tier: tierEl.value,
      }),
    });
    const data = await resp.json();
    if (resp.ok) {
      showToast(`用户 ${data.username} 创建成功（${data.tier}）`, "success");
      usernameEl.value = "";
      passwordEl.value = "";
      adminLoadUsers();
    } else {
      showToast(parseApiError(data), "error");
    }
  } catch (err) {
    showToast("创建失败: " + err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "创建";
  }
}

// ---------------------------------------------------------------------------
// Bootstrap: defer init() until views.js has injected views/*.html into
// #view-host. If views.js is already done by the time we get here (cache hit),
// the event listener catches the late dispatch via window.__enkoViewsReady.
// ---------------------------------------------------------------------------
function bootEnko() {
  if (window.__enkoInitDone) return;
  window.__enkoInitDone = true;
  document.documentElement.dataset.enkoInitStatus = "starting";
  init().catch((error) => {
    window.__enkoInitDone = false;
    document.documentElement.dataset.enkoInitStatus = "error";
    console.error("[enko-init]", error);
    showToast("控制台初始化失败: " + error.message, "error");
  }).then(() => {
    if (window.__enkoInitDone) document.documentElement.dataset.enkoInitStatus = "done";
  });
}

window.enkoInit = bootEnko;
window.enkoState = state;
window.enkoEls = els;
if (window.__enkoViewsReady) {
  bootEnko();
} else {
  window.addEventListener("enko-views-ready", bootEnko, { once: true });
}
