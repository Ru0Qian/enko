// ===========================================================================
// Enko Web Console — Method Analysis module
// ===========================================================================

let _methodAnalysisData = null;
let _methodMode = "recommended"; // "recommended" | "advanced"
let _methodSelections = {}; // spec -> level (0/1/2/3)
let _methodLastVisible = [];

const LEVEL_LABELS = { 0: "无保护", 1: "抽取", 2: "VMP", 3: "DEX2C" };
const LEVEL_PHASES = { 1: "extract", 2: "vmp", 3: "dex2c" };
const PHASE_LEVELS = { extract: 1, vmp: 2, dex2c: 3 };
const LEVEL_COLORS = {
  0: "text-slate-500 bg-slate-500/10",
  1: "text-secondary bg-secondary/10",
  2: "text-primary bg-primary/10",
  3: "text-tertiary bg-tertiary/10",
};

const SMART_PRESETS = {
  compat: {
    thresholds: { extract: 12, vmp: 28, dex2c: 38 },
    maxCount: 48,
    classCap: 1,
  },
  balanced: {
    thresholds: { extract: 8, vmp: 15, dex2c: 20 },
    maxCount: 96,
    classCap: 2,
  },
  strong: {
    thresholds: { extract: 4, vmp: 10, dex2c: 14 },
    maxCount: 180,
    classCap: 3,
  },
};

function initMethodAnalysis() {
  const analyzeBtn = document.getElementById("analyzeMethodsBtn");
  const toggleBtn = document.getElementById("toggleMethodMode");
  const acceptBtn = document.getElementById("acceptRecommended");
  const selectAll = document.getElementById("methodSelectAll");
  const searchInput = document.getElementById("methodSearchInput");
  const packageFilter = document.getElementById("methodPackageFilter");
  const smartPreset = document.getElementById("methodSmartPreset");
  const onlySelected = document.getElementById("methodOnlySelected");
  const smartSelect = document.getElementById("smartSelectFiltered");
  const clearFiltered = document.getElementById("clearFilteredSelection");

  if (analyzeBtn) analyzeBtn.addEventListener("click", runMethodAnalysis);
  if (acceptBtn) acceptBtn.addEventListener("click", acceptRecommendedMap);
  if (toggleBtn) toggleBtn.addEventListener("click", toggleMethodViewMode);
  if (selectAll) {
    selectAll.addEventListener("change", (e) => {
      document.querySelectorAll("#methodTableBody input[type=checkbox]").forEach((cb) => {
        cb.checked = e.target.checked;
        handleMethodCheck(cb);
      });
      updateSelectionSummary();
    });
  }
  if (searchInput) searchInput.addEventListener("input", debounceRenderAdvanced);
  if (packageFilter) packageFilter.addEventListener("change", debounceRenderAdvanced);
  if (smartPreset) {
    smartPreset.addEventListener("change", () => {
      if (_methodAnalysisData) runMethodAnalysis();
    });
  }
  if (onlySelected) onlySelected.addEventListener("change", renderAdvancedTable);
  if (smartSelect) smartSelect.addEventListener("click", smartSelectVisibleMethods);
  if (clearFiltered) clearFiltered.addEventListener("click", clearVisibleSelections);
}

let _advancedRenderTimer = null;
function debounceRenderAdvanced() {
  clearTimeout(_advancedRenderTimer);
  _advancedRenderTimer = setTimeout(() => renderAdvancedTable(), 150);
}

function getSmartPreset() {
  return document.getElementById("methodSmartPreset")?.value || "balanced";
}

function getEnabledPhases() {
  return {
    extract: els.featureExtract ? els.featureExtract.checked : true,
    vmp: els.featureVmpDex ? els.featureVmpDex.checked : true,
    dex2c: els.featureDex2c ? els.featureDex2c.checked : true,
  };
}

async function runMethodAnalysis(options = {}) {
  const { autoSaveRecommended = false, quiet = false } = options || {};
  const apkPath = els.inputApk.value.trim();
  if (!apkPath) {
    showToast("请先上传 APK 文件", "warning");
    return;
  }

  const statusEl = document.getElementById("methodAnalyzeStatus");
  const emptyEl = document.getElementById("methodEmptyState");
  const summaryEl = document.getElementById("methodSummaryBar");
  const recPanel = document.getElementById("methodRecommendedPanel");
  const advPanel = document.getElementById("methodAdvancedPanel");
  const toggleBtn = document.getElementById("toggleMethodMode");

  if (emptyEl) emptyEl.classList.add("hidden");
  if (summaryEl) summaryEl.classList.add("hidden");
  if (recPanel) recPanel.classList.add("hidden");
  if (advPanel) advPanel.classList.add("hidden");
  if (statusEl) statusEl.classList.remove("hidden");

  const analyzeBtn = document.getElementById("analyzeMethodsBtn");
  const labelEl = analyzeBtn ? analyzeBtn.querySelector("span:last-child") : null;
  if (analyzeBtn) analyzeBtn.disabled = true;
  if (labelEl) labelEl.textContent = "分析中...";

  try {
    const flutterMode = els.flutterMode ? els.flutterMode.checked : false;
    const resp = await authFetch("/api/analyze-methods", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        apk_path: apkPath,
        flutter_mode: flutterMode,
        selection_preset: getSmartPreset(),
        enabled_phases: getEnabledPhases(),
      }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(parseApiError(err) || "分析请求失败");
    }

    const data = await resp.json();
    _methodAnalysisData = data;
    _methodSelections = {};

    for (const [spec, info] of Object.entries(data.recommended || {})) {
      _methodSelections[spec] = info.level;
    }

    setText("methodTotalCount", data.total_methods);

    if (statusEl) statusEl.classList.add("hidden");
    if (summaryEl) summaryEl.classList.remove("hidden");
    if (toggleBtn) toggleBtn.classList.remove("hidden");

    _methodMode = "recommended";
    const modeLabel = document.getElementById("methodModeLabel");
    if (modeLabel) modeLabel.textContent = "高级模式";
    updateSelectionSummary();
    renderRecommendedTable();
    populatePackageFilter();
    if (recPanel) recPanel.classList.remove("hidden");

    if (autoSaveRecommended) {
      await acceptRecommendedMap({ quiet: true });
    }
    if (!quiet) {
      showToast(
        `分析完成：${data.total_methods} 个方法，${Object.keys(data.recommended || {}).length} 个推荐保护`,
        "success",
      );
    } else if (autoSaveRecommended) {
      showToast(
        `已自动分析并生成保护映射：${Object.keys(data.recommended || {}).length} 个推荐方法`,
        "success",
      );
    }
  } catch (error) {
    if (statusEl) statusEl.classList.add("hidden");
    if (emptyEl) emptyEl.classList.remove("hidden");
    showToast((quiet ? "自动方法分析失败: " : "方法分析失败: ") + error.message, quiet ? "warning" : "error");
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
    if (labelEl) labelEl.textContent = "智能分析";
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function renderRecommendedTable() {
  const tbody = document.getElementById("methodTableBody");
  if (!tbody || !_methodAnalysisData) return;

  const recommended = _methodAnalysisData.recommended || {};
  const entries = Object.entries(recommended).sort((a, b) => b[1].score - a[1].score);
  const selectAll = document.getElementById("methodSelectAll");
  if (selectAll) {
    selectAll.checked = entries.length > 0 && entries.every(([spec]) => (_methodSelections[spec] || 0) > 0);
  }

  tbody.innerHTML = entries.map(([spec, info]) => {
    const m = findMethod(spec);
    const parts = spec.split("->");
    const className = parts[0] || spec;
    const methodPart = parts[1] || "";
    const shortClass = className.split("/").pop().replace(";", "");
    const isChecked = (_methodSelections[spec] || 0) > 0;
    const curLevel = _methodSelections[spec] || info.level;
    const reasons = (info.reasons || []).slice(0, 4);

    return `<tr class="hover:bg-surface-bright/30 transition-colors">
      <td class="px-4 py-2.5"><input type="checkbox" ${isChecked ? "checked" : ""} data-spec="${_esc(spec)}" onchange="handleMethodCheck(this)" class="rounded"/></td>
      <td class="px-4 py-2.5">
        <div class="font-mono text-[11px] text-on-surface truncate max-w-sm" title="${_esc(spec)}">${_esc(shortClass)}<span class="text-slate-500">→</span>${_esc(methodPart)}</div>
        <div class="text-[10px] text-slate-500 mt-0.5">${reasons.map((r) => `<span class="inline-block mr-1 px-1.5 py-0.5 bg-surface-container rounded">${_esc(r)}</span>`).join("")}</div>
      </td>
      <td class="px-4 py-2.5 text-[10px] text-slate-400 font-mono">${_formatBytes(m ? m.code_bytes : 0)}</td>
      <td class="px-4 py-2.5"><span class="text-xs font-bold ${LEVEL_COLORS[curLevel] || ""} px-2 py-1 rounded">${info.score}</span></td>
      <td class="px-4 py-2.5">
        <select data-spec="${_esc(spec)}" onchange="handleLevelChange(this)" class="bg-surface-container border border-outline-variant/30 rounded px-2 py-1 text-[11px] ${LEVEL_COLORS[curLevel] || ""} font-bold">
          ${renderLevelOptions(curLevel)}
        </select>
      </td>
    </tr>`;
  }).join("");

  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-xs text-on-surface-variant">当前策略没有推荐方法，可切到高级模式手动选取。</td></tr>`;
  }
}

function renderLevelOptions(curLevel) {
  return [0, 1, 2, 3].map((level) => (
    `<option value="${level}" ${curLevel === level ? "selected" : ""}>${LEVEL_LABELS[level]}</option>`
  )).join("");
}

function findMethod(spec) {
  if (!_methodAnalysisData) return null;
  return (_methodAnalysisData.all_methods || []).find((m) => m.spec === spec) || null;
}

function _formatBytes(bytes) {
  if (bytes <= 0) return "-";
  if (bytes < 1024) return bytes + " B";
  return (bytes / 1024).toFixed(1) + " KB";
}

function _esc(str) {
  const d = document.createElement("div");
  d.textContent = String(str ?? "");
  return d.innerHTML;
}

function handleMethodCheck(checkbox) {
  const spec = checkbox.dataset.spec;
  if (!checkbox.checked) {
    _methodSelections[spec] = 0;
  } else {
    const rec = (_methodAnalysisData?.recommended || {})[spec];
    const method = findMethod(spec);
    _methodSelections[spec] = rec ? rec.level : bestLevelForMethod(method, true);
  }
  const row = checkbox.closest("tr");
  const sel = row ? row.querySelector("select") : null;
  if (sel) {
    sel.value = _methodSelections[spec] || 0;
    sel.className = selectClass(_methodSelections[spec] || 0);
  }
  updateSelectionSummary();
}

function handleLevelChange(select) {
  const spec = select.dataset.spec;
  const level = parseInt(select.value, 10);
  _methodSelections[spec] = level;
  select.className = selectClass(level);
  const row = select.closest("tr");
  const cb = row ? row.querySelector("input[type=checkbox]") : null;
  if (cb) cb.checked = level > 0;
  updateSelectionSummary();
}

function handleAdvLevelChange(select) {
  const spec = select.dataset.spec;
  const level = parseInt(select.value, 10);
  if (level > 0) {
    _methodSelections[spec] = level;
  } else {
    delete _methodSelections[spec];
  }
  select.className = selectClass(level);
  const row = select.closest("tr");
  const cb = row ? row.querySelector("input[type=checkbox]") : null;
  if (cb) cb.checked = level > 0;
  updateSelectionSummary();
  if (document.getElementById("methodOnlySelected")?.checked) renderAdvancedTable();
}

function handleAdvCheck(checkbox) {
  const spec = checkbox.dataset.spec;
  if (!checkbox.checked) {
    delete _methodSelections[spec];
  } else {
    _methodSelections[spec] = bestLevelForMethod(findMethod(spec), true);
  }
  const row = checkbox.closest("tr");
  const sel = row ? row.querySelector("select") : null;
  if (sel) {
    sel.value = _methodSelections[spec] || 0;
    sel.className = selectClass(_methodSelections[spec] || 0);
  }
  updateSelectionSummary();
  if (document.getElementById("methodOnlySelected")?.checked) renderAdvancedTable();
}

function selectClass(level) {
  return `bg-surface-container border border-outline-variant/30 rounded px-2 py-1 text-[11px] ${LEVEL_COLORS[level] || ""} font-bold`;
}

function toggleMethodViewMode() {
  const recPanel = document.getElementById("methodRecommendedPanel");
  const advPanel = document.getElementById("methodAdvancedPanel");
  const label = document.getElementById("methodModeLabel");

  if (_methodMode === "recommended") {
    _methodMode = "advanced";
    if (label) label.textContent = "推荐模式";
    if (recPanel) recPanel.classList.add("hidden");
    if (advPanel) advPanel.classList.remove("hidden");
    populatePackageFilter();
    renderAdvancedTable();
  } else {
    _methodMode = "recommended";
    if (label) label.textContent = "高级模式";
    if (advPanel) advPanel.classList.add("hidden");
    if (recPanel) recPanel.classList.remove("hidden");
    renderRecommendedTable();
  }
}

function populatePackageFilter() {
  const filter = document.getElementById("methodPackageFilter");
  if (!filter || !_methodAnalysisData) return;
  const counts = new Map();
  for (const m of _methodAnalysisData.all_methods || []) {
    counts.set(m.package, (counts.get(m.package) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  filter.innerHTML = `<option value="">全部包 (${sorted.length})</option>` +
    sorted.map(([p, count]) => `<option value="${_esc(p)}">${_esc(p)} (${count})</option>`).join("");
}

function filteredMethods() {
  if (!_methodAnalysisData) return [];
  const search = (document.getElementById("methodSearchInput")?.value || "").toLowerCase();
  const pkgFilter = document.getElementById("methodPackageFilter")?.value || "";
  const onlySelected = document.getElementById("methodOnlySelected")?.checked || false;

  let methods = _methodAnalysisData.all_methods || [];
  if (search) {
    methods = methods.filter((m) =>
      m.spec.toLowerCase().includes(search) ||
      m.package.toLowerCase().includes(search) ||
      (m.best_reasons || []).join(" ").toLowerCase().includes(search)
    );
  }
  if (pkgFilter) methods = methods.filter((m) => m.package === pkgFilter);
  if (onlySelected) methods = methods.filter((m) => (_methodSelections[m.spec] || 0) > 0);

  return [...methods].sort((a, b) =>
    Number(b.in_scope) - Number(a.in_scope) ||
    (b.best_score || 0) - (a.best_score || 0) ||
    (b.code_bytes || 0) - (a.code_bytes || 0) ||
    a.spec.localeCompare(b.spec)
  );
}

function renderAdvancedTable() {
  const tbody = document.getElementById("methodAdvancedBody");
  const countEl = document.getElementById("methodAdvancedCount");
  if (!tbody || !_methodAnalysisData) return;

  const methods = filteredMethods();
  const limited = methods.slice(0, 300);
  _methodLastVisible = limited;

  tbody.innerHTML = limited.map((m) => {
    const parts = m.spec.split("->");
    const shortClass = (parts[0] || "").split("/").pop().replace(";", "");
    const methodPart = parts[1] || "";
    const curLevel = _methodSelections[m.spec] || 0;
    const rec = (_methodAnalysisData.recommended || {})[m.spec];
    const checked = curLevel > 0;
    const scoreText = m.best_score ? `${m.best_score} · ${LEVEL_LABELS[m.best_level] || "无"}` : "-";
    const reasons = (m.best_reasons || []).slice(0, 3);

    return `<tr class="hover:bg-surface-bright/30 transition-colors${rec ? " bg-secondary/5" : ""}">
      <td class="px-4 py-2"><input type="checkbox" ${checked ? "checked" : ""} data-spec="${_esc(m.spec)}" onchange="handleAdvCheck(this)" class="rounded"/></td>
      <td class="px-4 py-2">
        <div class="font-mono text-[11px] text-on-surface truncate max-w-md" title="${_esc(m.spec)}">${_esc(shortClass)}<span class="text-slate-500">→</span>${_esc(methodPart)}</div>
        <div class="text-[10px] text-slate-600">
          ${_esc(m.package)}
          ${m.in_scope ? '<span class="text-primary ml-1">scope</span>' : ""}
          ${rec ? '<span class="text-secondary ml-1">推荐</span>' : ""}
          ${m.tries ? '<span class="text-amber-400 ml-1">try</span>' : ""}
        </div>
      </td>
      <td class="px-4 py-2 text-[10px] text-slate-400 font-mono">${_formatBytes(m.code_bytes)}</td>
      <td class="px-4 py-2">
        <span class="text-[10px] font-bold ${LEVEL_COLORS[m.best_level] || LEVEL_COLORS[0]} px-2 py-1 rounded">${_esc(scoreText)}</span>
        <div class="mt-1">${reasons.map((r) => `<span class="inline-block mr-1 text-[9px] text-slate-500">${_esc(r)}</span>`).join("")}</div>
      </td>
      <td class="px-4 py-2">
        <select data-spec="${_esc(m.spec)}" onchange="handleAdvLevelChange(this)" class="${selectClass(curLevel)}">
          ${renderLevelOptions(curLevel)}
        </select>
      </td>
    </tr>`;
  }).join("");

  if (!limited.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-xs text-on-surface-variant">当前过滤条件下没有方法。</td></tr>`;
  }

  if (countEl) countEl.textContent = `显示 ${limited.length} / ${methods.length} 个方法`;
}

function bestLevelForMethod(method, fallback = false) {
  if (!method) return fallback ? 1 : 0;
  const preset = SMART_PRESETS[getSmartPreset()] || SMART_PRESETS.balanced;
  const enabled = getEnabledPhases();
  let best = { level: 0, score: -9999, adjusted: -9999 };
  const phaseBonus = { extract: 0, vmp: 5, dex2c: 4 };

  for (const phase of ["extract", "vmp", "dex2c"]) {
    if (!enabled[phase]) continue;
    const score = method.scores?.[phase]?.score ?? -9999;
    if (score < preset.thresholds[phase]) continue;
    const adjusted = score + phaseBonus[phase];
    if (adjusted > best.adjusted) {
      best = { level: PHASE_LEVELS[phase], score, adjusted };
    }
  }
  if (best.level) return best.level;
  if (!fallback) return 0;
  if (method.best_level && enabled[LEVEL_PHASES[method.best_level]]) return method.best_level;
  if (enabled.extract) return 1;
  if (enabled.vmp) return 2;
  if (enabled.dex2c) return 3;
  return 0;
}

function smartSelectVisibleMethods() {
  if (!_methodAnalysisData) return;
  const preset = SMART_PRESETS[getSmartPreset()] || SMART_PRESETS.balanced;
  const candidates = filteredMethods()
    .map((m) => ({ method: m, level: bestLevelForMethod(m), score: m.best_score || 0 }))
    .filter((item) => item.level > 0)
    .sort((a, b) => b.score - a.score || b.method.code_bytes - a.method.code_bytes || a.method.spec.localeCompare(b.method.spec));

  const classCounts = new Map();
  let applied = 0;
  for (const m of filteredMethods()) {
    delete _methodSelections[m.spec];
  }
  for (const item of candidates) {
    if (applied >= preset.maxCount) break;
    const cls = item.method.class || item.method.spec.split("->")[0];
    const count = classCounts.get(cls) || 0;
    if (count >= preset.classCap) continue;
    _methodSelections[item.method.spec] = item.level;
    classCounts.set(cls, count + 1);
    applied += 1;
  }

  updateSelectionSummary();
  if (_methodMode === "advanced") renderAdvancedTable();
  else renderRecommendedTable();
  showToast(`已智能选取 ${applied} 个方法`, applied ? "success" : "warning");
}

function clearVisibleSelections() {
  const methods = filteredMethods();
  for (const m of methods) {
    delete _methodSelections[m.spec];
  }
  updateSelectionSummary();
  renderAdvancedTable();
  showToast(`已清空当前结果中的 ${methods.length} 个方法`, "info");
}

function updateSelectionSummary() {
  const counts = { 1: 0, 2: 0, 3: 0 };
  for (const level of Object.values(_methodSelections)) {
    if (level > 0) counts[level] = (counts[level] || 0) + 1;
  }
  setText("methodExtractCount", counts[1] || 0);
  setText("methodVmpCount", counts[2] || 0);
  setText("methodDex2cCount", counts[3] || 0);
  setText("methodSelectedCount", (counts[1] || 0) + (counts[2] || 0) + (counts[3] || 0));
}

async function acceptRecommendedMap(options = {}) {
  const { quiet = false } = options || {};
  const lines = Object.entries(_methodSelections)
    .filter(([, level]) => level > 0)
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
    .map(([spec, level]) => `${spec} ${level}`);

  if (lines.length === 0) {
    if (!quiet) showToast("没有选择任何方法进行保护", "warning");
    return;
  }

  try {
    const resp = await authFetch("/api/save-protection-map", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: lines.join("\n") + "\n" }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(parseApiError(err) || "保存失败");
    }
    const data = await resp.json();
    els.protectionMap.value = data.path;
    renderCommand();
    if (!quiet) showToast(`已生成保护映射表：${lines.length} 个方法`, "success");
  } catch (error) {
    showToast("保存映射表失败: " + error.message, quiet ? "warning" : "error");
  }
}

initMethodAnalysis();
