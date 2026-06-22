// ===========================================================================
// Enko Web Console — Report and stack-list rendering helpers
// ===========================================================================

function buildJobReportSummary(job, report) {
  if (!report) {
    return [
      {
        title: "报告状态",
        body: job.report_exists ? "报告已生成，刷新后会自动载入详情。" : "任务完成后会在这里显示 report.json 摘要。",
        state: job.report_exists ? "partial" : "partial",
      },
    ];
  }

  const methodProtection = report.method_protection || {};
  const compiled = report.compiled || {};
  const vmpObf = methodProtection.vmp_obfuscation || {};
  const vmpFormat = methodProtection.vmp_bytecode_format || {};
  const vmpCore = methodProtection.vmp_interpreter_core || {};
  const d2cObf = methodProtection.dex2c_native_obfuscation || {};
  const shellPoly = report.shell_polymorphism || {};
  const envelope = report.payload_envelope || {};
  const controls = report.controls || [];
  const enabledControls = controls.filter((c) => c.enabled !== false).length;
  const fallbackUsed = Boolean(d2cObf.fallback_used);
  const vmpDowngraded = Boolean(vmpObf.downgraded);
  const aliasVariantCount = Object.values(vmpFormat.semantic_alias_handler_variants || {})
    .reduce((sum, value) => sum + Number(value || 0), 0);

  return [
    {
      title: "安全评分",
      body: `${report.score ?? "-"} / ${report.max_score ?? 100}，grade ${report.grade ?? "-"}`,
      state: (report.score ?? 0) >= 80 ? "enabled" : "partial",
    },
    {
      title: "方法保护",
      body: `extract ${compiled.extract ?? 0} / vmp ${compiled.vmp_dex ?? 0} / dex2c ${compiled.dex2c ?? 0}，覆盖 ${percent(methodProtection.protectable_coverage_ratio)}`,
      state: (methodProtection.compiled_total || 0) > 0 ? "enabled" : "partial",
    },
    {
      title: "VMP 混淆",
      body: `split ${vmpObf.effective_split_prob ?? vmpObf.split_prob ?? "-"} / junk ${vmpObf.effective_junk_ratio ?? vmpObf.junk_ratio ?? "-"}，字符串池 v${vmpObf.string_pool_format_version ?? "-"}${vmpDowngraded ? `，已降级：${vmpObf.downgrade_reason || "兼容回退"}` : ""}`,
      state: vmpDowngraded ? "partial" : "enabled",
    },
    {
      title: "VMP 指令格式",
      body: `${vmpFormat.instruction_encoding || "unknown"}，${vmpFormat.instruction_width_bytes || "-"} bytes，字段随机 ${vmpFormat.field_layout_randomized ? "yes" : "no"}，可变长 ${vmpFormat.variable_length_supported ? "yes" : "no"}，语义别名 ${aliasVariantCount || 0}`,
      state: vmpFormat.variable_length_supported ? "enabled" : "partial",
    },
    {
      title: "VMP VM 档位",
      body: `requested ${vmpCore.requested_tier || "-"} / effective ${vmpCore.effective_tier || "-"}，payload ${vmpCore.payload_tier || "-"}，shell ${vmpCore.shell_tier || "-"}`,
      state: vmpCore.partitioning_enabled ? "enabled" : "partial",
    },
    {
      title: "DEX2C OLLVM",
      body: `${d2cObf.ollvm_effective ? "已保护" : d2cObf.ollvm_enabled ? "等待或回退" : "未启用"}，preflight ${d2cObf.preflight_status || "-"}，ABI ${(d2cObf.ollvm_protected_abis || []).join(", ") || "-"}`,
      state: d2cObf.ollvm_effective ? "enabled" : fallbackUsed ? "partial" : "partial",
    },
    {
      title: "Payload Envelope",
      body: `padding ${envelope.padding_length ?? 0} bytes，inner ${envelope.inner_length ?? "-"}，wrapped ${envelope.wrapped_length ?? "-"}`,
      state: envelope.padding_length ? "enabled" : "partial",
    },
    {
      title: "壳多态",
      body: shellPoly.package ? `${shellPoly.package}，class ${shellPoly.class_alias_count || 0} / method ${shellPoly.method_alias_count || 0} / field ${shellPoly.field_alias_count || 0}` : "未启用",
      state: shellPoly.package ? "enabled" : "partial",
    },
    aiDecoySummary(report),
    {
      title: "安全控制项",
      body: `${enabledControls}/${controls.length || 0} 已启用，建议 ${report.recommendations?.length || 0} 项`,
      state: report.recommendations?.length ? "partial" : "enabled",
    },
  ];
}

function aiDecoySummary(report) {
  const decoy = report.ai_decoy || {};
  if (!decoy.enabled) {
    return {
      title: "AI 诱饵 / canary",
      body: "未启用（强保护或商业模式建议开启）",
      state: "partial",
    };
  }
  const files = decoy.injected_files || [];
  const fileList = files.length ? files.join("、") : "无";
  return {
    title: "AI 诱饵 / canary",
    body: `canary <code class="font-mono text-tertiary">${(decoy.canary || "").replace(/[<&>]/g, "")}</code>，注入 ${decoy.injected_count || 0} 个诱饵：${fileList}`,
    state: "enabled",
  };
}

function describeSecurityControl(control) {
  if (control.name === "signed-output") {
    if (control.mode === "in-pipeline") {
      return {
        title: "输出签名",
        body: `加固端已用原证书签名 · points ${control.points}/${control.weight}`,
      };
    }
    if (control.mode === "external-original-certificate") {
      return {
        title: "外部原证书签名",
        body: `产物待业务方用同证书重签 · points ${control.points}/${control.weight}`,
      };
    }
    return {
      title: "输出签名",
      body: `缺少原证书签名链 · points ${control.points}/${control.weight}`,
    };
  }
  if (control.name === "runtime-signature-pin") {
    return {
      title: "运行时证书 Pin",
      body: `绑定原 APK 签名 SHA-256 · points ${control.points}/${control.weight}`,
    };
  }
  return {
    title: control.name,
    body: `points ${control.points}/${control.weight}`,
  };
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
  const vmpFormat = methodProtection.vmp_bytecode_format || {};
  const vmpCore = methodProtection.vmp_interpreter_core || {};
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
      ...describeSecurityControl(control),
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
    {
      title: "VMP bytecode",
      body: `${vmpFormat.instruction_encoding || "unknown"} · blob v${vmpFormat.blob_version ?? "-"} · layout ${(vmpFormat.field_layout || []).join(", ") || "-"}`,
      state: vmpFormat.variable_length_supported ? "enabled" : "partial",
    },
    {
      title: "VM tier",
      body: `${vmpCore.effective_tier || "-"} · ${vmpCore.method_partition_strategy || "-"}`,
      state: vmpCore.partitioning_enabled ? "enabled" : "partial",
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
      showToast("report.json 解析失败，请确认文件格式正确。", "error");
    }
  };
  reader.readAsText(file, "utf-8");
}
