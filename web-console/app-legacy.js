const state = {
  profile: "flutter_prod",
  target: "flutter",
  riskPolicy: "block",
  riskProfile: "strict",
  flutterMode: true,
  commercialMode: false,
  signingEnabled: false,
  perApkKey: true,
  detectRoot: true,
  detectEmulator: true,
  blockProxyVpn: true,
  releaseManifestEnabled: false,
  environment: {
    sdk_root: "",
    build_tools: "",
    ndk: "",
    apktool: "",
    zipalign: "",
    apksigner: "",
  },
  features: {
    extract: true,
    vmpDex: true,
    dex2c: true,
    vmpShellDex: false,
    polymorphicShell: false,
  },
  activeJobId: null,
  pollTimer: null,
};

const profileNames = {
  flutter_prod: "Flutter 生产",
  android_prod: "Android 生产",
  lab_debug: "实验室验证",
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
    { name: "signed-output", points: 20, weight: 20, enabled: true },
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

const els = {
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
  commercialMode: document.getElementById("commercialMode"),
  flutterMode: document.getElementById("flutterMode"),
  signingEnabled: document.getElementById("signingEnabled"),
  perApkKey: document.getElementById("perApkKey"),
  detectRoot: document.getElementById("detectRoot"),
  detectEmulator: document.getElementById("detectEmulator"),
  blockProxyVpn: document.getElementById("blockProxyVpn"),
  releaseManifestEnabled: document.getElementById("releaseManifestEnabled"),
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
  jobLog: document.getElementById("jobLog"),
};

async function init() {
  bindProfileButtons();
  bindTargetButtons();
  bindPolicyButtons();
  bindRiskButtons();
  bindFields();
  renderGates();
  await loadEnvironment();
  applyProfile(state.profile);
  renderReport(sampleReport);
  renderJob(null);
}

async function loadEnvironment() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    if (!response.ok || !payload.defaults) {
      return;
    }
    state.environment = payload.defaults;
    if (isPlaceholderNdk(els.ndkPath.value) && payload.defaults.ndk) {
      els.ndkPath.value = payload.defaults.ndk;
    }
  } catch (error) {
    console.warn("failed to load environment defaults", error);
  }
}

function maxReachableSecurityScore(config) {
  let score = 85;
  if (config.signingEnabled) {
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
      renderCommand();
    });
  });
}

function bindPolicyButtons() {
  document.querySelectorAll("[data-policy]").forEach((button) => {
    button.addEventListener("click", () => {
      state.riskPolicy = button.dataset.policy;
      syncGroup("[data-policy]", state.riskPolicy);
      renderCommand();
    });
  });
}

function bindRiskButtons() {
  document.querySelectorAll("[data-risk]").forEach((button) => {
    button.addEventListener("click", () => {
      state.riskProfile = button.dataset.risk;
      syncGroup("[data-risk]", state.riskProfile);
      renderCommand();
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
    els.minExtract,
    els.minVmp,
    els.minDex2c,
    els.minScore,
    els.keystorePath,
    els.ksPass,
    els.keyAlias,
    els.keyPass,
  ].forEach((input) => input.addEventListener("input", renderCommand));

  [
    ["featureExtract", els.featureExtract],
    ["featureVmpDex", els.featureVmpDex],
    ["featureDex2c", els.featureDex2c],
    ["featureVmpShellDex", els.featureVmpShellDex],
    ["featurePolymorphicShell", els.featurePolymorphicShell],
    ["commercialMode", els.commercialMode],
    ["flutterMode", els.flutterMode],
    ["signingEnabled", els.signingEnabled],
    ["perApkKey", els.perApkKey],
    ["detectRoot", els.detectRoot],
    ["detectEmulator", els.detectEmulator],
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
      } else {
        state[key] = input.checked;
      }

      if (key === "commercialMode" && input.checked && !els.signingEnabled.checked) {
        els.signingEnabled.checked = true;
        state.signingEnabled = true;
      }
      if (key === "signingEnabled" && !input.checked && els.commercialMode.checked) {
        els.commercialMode.checked = false;
        state.commercialMode = false;
      }
      if (key === "flutterMode") {
        state.target = input.checked ? "flutter" : "android";
        syncGroup("[data-target]", state.target);
      }

      if (key === "commercialMode" || key === "signingEnabled") {
        normalizeScoreGate(collectConfig(), true);
      }

      renderCommand();
    });
  });

  els.copyCommand.addEventListener("click", copyCommand);
  els.startHardening.addEventListener("click", startHardening);
  els.reportFile.addEventListener("change", handleReportUpload);
  els.loadSample.addEventListener("click", () => renderReport(sampleReport));
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
    },
  };

  const profiles = {
    flutter_prod: {
      ...common,
      target: "flutter",
      flutterMode: true,
      riskPolicy: "block",
      riskProfile: "strict",
      detectRoot: true,
      detectEmulator: true,
      blockProxyVpn: true,
      minExtract: 120,
      minVmp: 30,
      minDex2c: 15,
      minScore: 80,
      protectionMap: "D:\\Engineering\\projects\\enko\\en\\auto-protect-flutter.txt",
      outputApk: "D:\\Engineering\\projects\\enko\\output\\flutter-hardened.apk",
    },
    android_prod: {
      ...common,
      target: "android",
      flutterMode: false,
      riskPolicy: "block",
      riskProfile: "strict",
      detectRoot: true,
      detectEmulator: true,
      blockProxyVpn: true,
      minExtract: 40,
      minVmp: 20,
      minDex2c: 5,
      minScore: 80,
      protectionMap: "D:\\Engineering\\projects\\enko\\auto-protect-demo.txt",
      outputApk: "D:\\Engineering\\projects\\enko\\output\\android-hardened.apk",
    },
    lab_debug: {
      ...common,
      target: "flutter",
      flutterMode: true,
      riskPolicy: "log",
      riskProfile: "compat",
      detectRoot: false,
      detectEmulator: false,
      blockProxyVpn: false,
      minExtract: 0,
      minVmp: 0,
      minDex2c: 0,
      minScore: 0,
      protectionMap: "D:\\Engineering\\projects\\enko\\en\\auto-protect-flutter.txt",
      outputApk: "D:\\Engineering\\projects\\enko\\output\\lab-hardened.apk",
    },
  };

  Object.assign(state, profiles[profile]);
  state.features = { ...profiles[profile].features };

  els.featureExtract.checked = state.features.extract;
  els.featureVmpDex.checked = state.features.vmpDex;
  els.featureDex2c.checked = state.features.dex2c;
  if (els.featureVmpShellDex) els.featureVmpShellDex.checked = state.features.vmpShellDex;
  if (els.featurePolymorphicShell) els.featurePolymorphicShell.checked = state.features.polymorphicShell;
  els.flutterMode.checked = state.flutterMode;
  els.commercialMode.checked = state.commercialMode;
  els.signingEnabled.checked = state.signingEnabled;
  els.perApkKey.checked = state.perApkKey;
  els.detectRoot.checked = state.detectRoot;
  els.detectEmulator.checked = state.detectEmulator;
  els.blockProxyVpn.checked = state.blockProxyVpn;
  els.releaseManifestEnabled.checked = state.releaseManifestEnabled;
  els.protectionMap.value = state.protectionMap;
  els.outputApk.value = state.outputApk;
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

function collectConfig() {
  return normalizeScoreGate({
    inputApk: els.inputApk.value.trim(),
    shellApk: els.shellApk.value.trim(),
    outputApk: els.outputApk.value.trim(),
    ndkPath: els.ndkPath.value.trim(),
    protectionMap: els.protectionMap.value.trim(),
    reportJsonPath: els.reportJsonPath.value.trim(),
    keystorePath: els.keystorePath.value.trim(),
    ksPass: els.ksPass.value,
    keyAlias: els.keyAlias.value.trim(),
    keyPass: els.keyPass.value,
    riskPolicy: state.riskPolicy,
    riskProfile: state.riskProfile,
    commercialMode: els.commercialMode.checked,
    flutterMode: els.flutterMode.checked,
    signingEnabled: els.signingEnabled.checked,
    perApkKey: els.perApkKey.checked,
    detectRoot: els.detectRoot.checked,
    detectEmulator: els.detectEmulator.checked,
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
  });
}

function renderCommand() {
  const config = collectConfig();

  state.flutterMode = config.flutterMode;
  state.commercialMode = config.commercialMode;
  state.signingEnabled = config.signingEnabled;
  state.perApkKey = config.perApkKey;
  state.detectRoot = config.detectRoot;
  state.detectEmulator = config.detectEmulator;
  state.blockProxyVpn = config.blockProxyVpn;
  state.releaseManifestEnabled = config.releaseManifestEnabled;
  state.features.extract = config.featureExtract;
  state.features.vmpDex = config.featureVmpDex;
  state.features.dex2c = config.featureDex2c;
  state.features.vmpShellDex = config.featureVmpShellDex;
  state.features.polymorphicShell = config.featurePolymorphicShell;

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
    lines.push('  --release-manifest "D:\\Engineering\\projects\\enko\\release\\release_manifest.json" `');
  }
  if (config.featureVmpShellDex) {
    lines.push("  --vmp-shell-dex `");
  }
  if (config.featurePolymorphicShell) {
    lines.push("  --polymorphic-shell `");
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
  els.signingBox.style.display = config.signingEnabled ? "block" : "none";
  els.profileBadge.textContent = profileNames[state.profile];
  els.heroMode.textContent = config.flutterMode ? "Flutter" : "Android";
  els.heroPolicy.textContent = `${config.riskPolicy} / ${config.riskProfile}`;
  els.heroGateCount.textContent = config.flutterMode ? "6 + native-core" : "6";
}

function syncGroup(selector, value) {
  document.querySelectorAll(selector).forEach((button) => {
    const matched =
      button.dataset.profile === value ||
      button.dataset.target === value ||
      button.dataset.policy === value ||
      button.dataset.risk === value;
    button.classList.toggle("active", matched);
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

async function startHardening() {
  const config = collectConfig();
  if (!config.inputApk || !config.shellApk || !config.outputApk) {
    window.alert("请先填写输入 APK、壳 APK 和输出 APK。");
    return;
  }
  if (!config.featureExtract && !config.featureVmpDex && !config.featureDex2c) {
    window.alert("至少保留一种方法保护功能，不然 protection map 没有意义。");
    return;
  }

  els.startHardening.disabled = true;
  els.startHardening.textContent = "提交中...";

  try {
    const response = await fetch("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "启动任务失败");
    }

    state.activeJobId = payload.job.id;
    renderJob(payload.job);
    startPolling();
  } catch (error) {
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

function startPolling() {
  stopPolling();
  pollJob();
  state.pollTimer = window.setInterval(pollJob, 1500);
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
    const response = await fetch(`/api/jobs/${encodeURIComponent(state.activeJobId)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "查询任务状态失败");
    }

    renderJob(payload.job);
    if (payload.job.status === "succeeded" || payload.job.status === "failed") {
      stopPolling();
    }
  } catch (error) {
    renderJob({
      id: state.activeJobId,
      status: "failed",
      error: error.message,
      log: [`[web-console] ${error.message}`],
    });
    stopPolling();
  }
}

function renderJob(job) {
  const safeJob = job || {};
  const status = safeJob.status || "idle";
  const badgeClass = status === "succeeded" ? "good" : status === "running" ? "warn" : status === "failed" ? "bad" : "idle";

  els.jobStatusBadge.textContent = status;
  els.jobStatusBadge.className = `badge status-badge ${badgeClass}`;
  els.jobIdValue.textContent = safeJob.id || "-";
  els.jobReturnCode.textContent =
    safeJob.returncode === null || safeJob.returncode === undefined ? "-" : String(safeJob.returncode);
  els.jobDuration.textContent = buildDurationText(safeJob);
  els.jobOutputApk.textContent = safeJob.output_apk || "-";
  els.jobReportPath.textContent = safeJob.report_json || "-";
  els.jobLog.textContent = (safeJob.log || []).join("\n") || "还没有任务。点击“开始加固”后，这里会显示本地 harden_apk.py 的输出。";

  const toolSummary = buildToolSummary(safeJob.resolved_tools || state.environment, safeJob.resolved_ndk || resolveNdkPath(els.ndkPath.value));
  const scoreGateSummary = buildScoreGateSummary(safeJob);

  renderStackList(els.jobMetaList, [
    {
      title: "当前状态",
      body: describeStatus(status, safeJob.error),
      state: status === "succeeded" ? "enabled" : status === "running" ? "partial" : status === "failed" ? "missing" : "partial",
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

  els.jobLog.scrollTop = els.jobLog.scrollHeight;
}

function describeStatus(status, error) {
  if (status === "running") {
    return "任务正在执行，本地服务会持续刷新日志。";
  }
  if (status === "succeeded") {
    return "任务已完成，可以直接去拿输出 APK 和 report.json。";
  }
  if (status === "failed") {
    return error || "任务失败，请先看日志里报错位置。";
  }
  return "还没有启动任务。";
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

function buildDurationText(job) {
  if (!job.started_at) {
    return "尚未执行";
  }
  if (!job.finished_at) {
    return `开始于 ${formatClock(job.started_at)}`;
  }
  return `${formatClock(job.started_at)} - ${formatClock(job.finished_at)}`;
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

function renderGates() {
  const template = document.getElementById("gateTemplate");
  els.gatesFlow.innerHTML = "";
  gateDefinitions.forEach((gate, index) => {
    const node = template.content.firstElementChild.cloneNode(true);
    node.querySelector(".gate-step").textContent = index + 1;
    node.querySelector("h3").textContent = gate.title;
    node.querySelector("p").textContent = gate.desc;
    els.gatesFlow.appendChild(node);
  });
}

function renderReport(report) {
  const nativeCore = report.target_runtime?.native_core || {};
  const methodProtection = report.method_protection || {};
  const controls = report.controls || [];
  const recommendations = report.recommendations || [];

  els.scoreValue.textContent = `${report.score ?? 0} / ${report.max_score ?? 100}`;
  els.gradeValue.textContent = report.grade ?? "-";
  els.modeValue.textContent = report.target_runtime?.mode ?? "standard";
  els.policyValue.textContent = `${report.risk_policy ?? "-"} / ${report.risk_profile ?? "-"}`;
  els.coverageValue.textContent = percent(methodProtection.protectable_coverage_ratio);
  els.coverageRole.textContent = methodProtection.role ?? "primary";

  const nativePinnedCount =
    (nativeCore.libapp?.integrity_pinned ? 1 : 0) +
    (nativeCore.libflutter?.integrity_pinned ? 1 : 0);
  const nativePresentCount =
    (nativeCore.libapp?.present ? 1 : 0) +
    (nativeCore.libflutter?.present ? 1 : 0);

  els.nativeCoreValue.textContent = `${nativePinnedCount} / ${nativePresentCount || 0}`;
  els.hookTargetsValue.textContent = (nativeCore.hook_watch_targets || ["agpcore"]).join(", ");

  renderStackList(
    els.controlsList,
    controls.map((control) => ({
      title: control.name,
      body: `points ${control.points}/${control.weight}`,
      state: control.points >= control.weight ? "enabled" : "partial",
    }))
  );

  renderStackList(els.nativeCoreList, [
    {
      title: "libapp.so",
      body: nativeCore.libapp?.present
        ? `${nativeCore.libapp.path_count} 个 ABI，integrity ${nativeCore.libapp.integrity_pinned ? "pinned" : "missing"}`
        : "未发现",
      state: nativeCore.libapp?.integrity_pinned ? "enabled" : nativeCore.libapp?.present ? "partial" : "missing",
    },
    {
      title: "libflutter.so",
      body: nativeCore.libflutter?.present
        ? `${nativeCore.libflutter.path_count} 个 ABI，integrity ${nativeCore.libflutter.integrity_pinned ? "pinned" : "missing"}`
        : "未发现",
      state: nativeCore.libflutter?.integrity_pinned ? "enabled" : nativeCore.libflutter?.present ? "partial" : "missing",
    },
    {
      title: "Hook Watch Targets",
      body: (nativeCore.hook_watch_targets || ["agpcore"]).join(", "),
      state: "enabled",
    },
  ]);

  renderStackList(els.methodStats, [
    {
      title: "Compiled",
      body: `extract ${report.compiled?.extract ?? 0} / vmp ${report.compiled?.vmp_dex ?? 0} / dex2c ${report.compiled?.dex2c ?? 0}`,
      state: "enabled",
    },
    {
      title: "Coverage",
      body: `${percent(methodProtection.protectable_coverage_ratio)}，grade ${methodProtection.coverage_grade ?? "-"}`,
      state: "enabled",
    },
    {
      title: "Role",
      body: methodProtection.role ?? "primary",
      state: methodProtection.role === "secondary" ? "partial" : "enabled",
    },
  ]);

  renderStackList(
    els.recommendationsList,
    recommendations.length
      ? recommendations.map((item) => ({
          title: item,
          body: "这项在当前配置里还可以继续补强。",
          state: "partial",
        }))
      : [
          {
            title: "没有阻塞建议",
            body: "当前示例报告没有必须立刻补的短板。",
            state: "enabled",
          },
        ]
  );
}

function renderStackList(container, items) {
  container.innerHTML = "";
  items.forEach((item) => {
    const row = document.createElement("article");
    row.className = "stack-item";
    row.innerHTML = `
      <div>
        <strong>${escapeHtml(item.title)}</strong>
        <small>${escapeHtml(item.body)}</small>
      </div>
      <span class="stack-state ${stateClass(item.state)}">${labelState(item.state)}</span>
    `;
    container.appendChild(row);
  });
}

function handleReportUpload(event) {
  const [file] = event.target.files || [];
  if (!file) {
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const report = JSON.parse(String(reader.result));
      renderReport(report);
    } catch (error) {
      window.alert("report.json 解析失败，请确认文件格式正确。");
    }
  };
  reader.readAsText(file, "utf-8");
}

function resolveNdkPath(configValue) {
  if (configValue && !isPlaceholderNdk(configValue)) {
    return configValue;
  }
  return state.environment.ndk || "";
}

function isPlaceholderNdk(value) {
  const lowered = String(value || "").trim().toLowerCase();
  return !lowered || lowered.includes("your-version");
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

init();
