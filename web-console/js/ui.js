/* ============================================================================
 * Enko Web Console — shared UI helpers
 *
 *   ui.theme.init()           — apply persisted theme on boot
 *   ui.theme.toggle()         — flip dark<->light, persist, fire event
 *   ui.theme.set(name)        — explicit set
 *   ui.statusBadge({label,kind}) — render <span class="badge ..."> string
 *   ui.tooltip(targetEl, html)  — attach a hover tooltip (lightweight)
 *   ui.segmented(group, opts) — render a segmented control HTML
 *   ui.panel({icon,title,body,footer}) — wrap content in a glass-panel
 *   ui.copyToClipboard(text, btnEl) — copy + brief inline ack
 *
 * All helpers are framework-free; they return HTML strings or attach handlers.
 * Loaded BEFORE app.js / jobs.js / report.js / analyzer.js.
 * ============================================================================ */
(function (window) {
  "use strict";

  const THEME_KEY = "enko_theme";
  const VALID_THEMES = new Set(["dark", "light"]);

  function getStoredTheme() {
    try {
      const v = localStorage.getItem(THEME_KEY);
      return VALID_THEMES.has(v) ? v : null;
    } catch (_) { return null; }
  }

  function preferredTheme() {
    const stored = getStoredTheme();
    if (stored) return stored;
    try {
      if (window.matchMedia &&
          window.matchMedia("(prefers-color-scheme: light)").matches) {
        return "light";
      }
    } catch (_) {}
    return "dark";
  }

  function applyTheme(name) {
    if (!VALID_THEMES.has(name)) name = "dark";
    document.documentElement.setAttribute("data-theme", name);
    try { localStorage.setItem(THEME_KEY, name); } catch (_) {}
    window.dispatchEvent(new CustomEvent("enko-theme-change", { detail: { theme: name } }));
  }

  const theme = {
    init() {
      applyTheme(preferredTheme());
      this._wireToggleButtons();
    },
    set(name) { applyTheme(name); },
    toggle() {
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      applyTheme(cur === "dark" ? "light" : "dark");
    },
    current() {
      return document.documentElement.getAttribute("data-theme") || "dark";
    },
    _wireToggleButtons() {
      document.querySelectorAll("[data-theme-toggle]").forEach(btn => {
        if (btn.dataset.themeWired === "1") return;
        btn.dataset.themeWired = "1";
        btn.addEventListener("click", () => theme.toggle());
      });
    },
  };

  // ---- statusBadge -------------------------------------------------------
  // kind: good | warn | bad | idle | primary
  function statusBadge({ label, kind }) {
    const safe = String(label || "").replace(/[<&>]/g, c =>
      ({ "<": "&lt;", "&": "&amp;", ">": "&gt;" }[c]));
    const k = ["good", "warn", "bad", "idle", "primary"].includes(kind) ? kind : "idle";
    return `<span class="badge ${k}">${safe}</span>`;
  }

  // ---- tooltip -----------------------------------------------------------
  function tooltip(targetEl, html) {
    if (!targetEl) return;
    const tip = document.createElement("div");
    tip.className = "absolute z-50 max-w-xs p-2.5 rounded-lg shadow-xl text-[11px] leading-relaxed pointer-events-none transition-opacity opacity-0";
    tip.style.background = "var(--c-modal-bg)";
    tip.style.border = "1px solid var(--c-outline)";
    tip.style.color = "var(--c-text-secondary)";
    tip.innerHTML = html;
    targetEl.style.position = targetEl.style.position || "relative";
    targetEl.appendChild(tip);
    const show = () => {
      tip.style.opacity = "1";
      const rect = targetEl.getBoundingClientRect();
      tip.style.bottom = (rect.height + 6) + "px";
      tip.style.left = "50%";
      tip.style.transform = "translateX(-50%)";
    };
    const hide = () => { tip.style.opacity = "0"; };
    targetEl.addEventListener("mouseenter", show);
    targetEl.addEventListener("mouseleave", hide);
    targetEl.addEventListener("focusin", show);
    targetEl.addEventListener("focusout", hide);
  }

  // ---- segmented ---------------------------------------------------------
  // Generates a segmented control HTML; caller is responsible for wiring
  // selection state via data-* attrs (existing app.js pattern).
  //   ui.segmented("data-policy", [
  //     {value:"block", label:"阻断",  hint:"商业推荐"},
  //     ...
  //   ])
  function segmented(dataAttr, options) {
    const parts = options.map((opt, idx) => {
      const checked = idx === 0 ? "checked" : "";
      return `<label class="segment-item flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer text-xs">
        <input type="radio" name="${dataAttr}" ${dataAttr}="${opt.value}" value="${opt.value}" ${checked} class="sr-only">
        <span class="font-medium">${opt.label}</span>
        ${opt.hint ? `<span class="text-[10px] opacity-70">${opt.hint}</span>` : ""}
      </label>`;
    }).join("");
    return `<div class="segmented-group flex flex-wrap gap-2">${parts}</div>`;
  }

  // ---- panel -------------------------------------------------------------
  // Render a glass-panel wrapper around content.
  function panel({ icon, title, subtitle, bodyHTML, footerHTML, accent }) {
    const accentCls = accent || "primary";
    return `<section class="glass-panel rounded-xl shadow-xl mb-6 overflow-hidden">
      <header class="flex items-center gap-3 p-5 border-b" style="border-color: var(--c-outline-soft);">
        ${icon ? `<div class="p-2 rounded-lg" style="background: var(--c-tint-${accentCls});">
          <span class="material-symbols-outlined" style="color: var(--c-${accentCls});">${icon}</span>
        </div>` : ""}
        <div class="flex-1 min-w-0">
          <h2 class="text-h3 font-headline">${title || ""}</h2>
          ${subtitle ? `<p class="text-xs" style="color: var(--c-text-tertiary);">${subtitle}</p>` : ""}
        </div>
      </header>
      <div class="p-5">${bodyHTML || ""}</div>
      ${footerHTML ? `<footer class="p-5 border-t" style="border-color: var(--c-outline-soft);">${footerHTML}</footer>` : ""}
    </section>`;
  }

  // ---- clipboard ---------------------------------------------------------
  async function copyToClipboard(text, ackBtn) {
    try {
      await navigator.clipboard.writeText(text);
      if (ackBtn) {
        const old = ackBtn.textContent;
        ackBtn.textContent = "已复制";
        setTimeout(() => { ackBtn.textContent = old; }, 1400);
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  // ---- exports -----------------------------------------------------------
  window.ui = {
    theme,
    statusBadge,
    tooltip,
    segmented,
    panel,
    copyToClipboard,
  };

  // Auto-init theme as early as possible (before app.js loads big DOM).
  // The toggle wiring is re-run by app.js after main DOM is ready.
  if (document.readyState !== "loading") {
    theme.init();
  } else {
    document.addEventListener("DOMContentLoaded", () => theme.init(), { once: true });
  }
})(window);
