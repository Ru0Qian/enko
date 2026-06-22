/* ============================================================================
 * Enko Web Console — view loader
 *
 * Stage 2 of the UI refactor: index.html now only ships the shell (sidebar,
 * topbar, modals, hidden fields) and an empty <div id="view-host">. The seven
 * <section id="view-X"> blocks live in views/*.html and are fetched + injected
 * here BEFORE app.js runs its `init()`, so every `document.getElementById`
 * call in app.js still finds the DOM it expects.
 *
 * Ordering contract:
 *   1. <script src="js/ui.js"> runs (theme init, helpers).
 *   2. <script src="js/views.js"> runs SYNCHRONOUSLY at end of <body> and
 *      blocks the rest of <body> by listening for DOMContentLoaded.
 *   3. Once views are injected, we set window.__enkoViewsReady and fire the
 *      'enko-views-ready' event.
 *   4. app.js's init() is called from this event (we wrap it), so the order
 *      becomes deterministic with or without WebSocket / network jitter.
 * ============================================================================ */
(function () {
  "use strict";

  const VIEW_NAMES = [
    "dashboard", "new-job", "jobs", "job-detail",
    "reports", "profiles", "admin",
  ];

  // Fetch all views in parallel.
  async function loadViews() {
    const host = document.getElementById("view-host");
    if (!host) {
      console.error("[views] #view-host missing from index.html");
      return false;
    }

    const fetchOne = async (name) => {
      const url = `views/${name}.html`;
      const resp = await fetch(url, { credentials: "same-origin", cache: "no-cache" });
      if (!resp.ok) throw new Error(`failed to load ${url}: ${resp.status}`);
      return { name, html: await resp.text() };
    };

    let pieces;
    try {
      pieces = await Promise.all(VIEW_NAMES.map(fetchOne));
    } catch (err) {
      console.error("[views] load failed:", err);
      host.innerHTML = `<div class="p-8 text-error">视图加载失败: ${err.message}</div>`;
      return false;
    }

    // Inject in the original order so view-section CSS animation order is stable.
    host.innerHTML = pieces.map(p => p.html).join("\n");
    return true;
  }

  // Hold off until DOM is parsed (so #view-host exists), then load views and
  // run app.js's init.
  function bootstrap() {
    loadViews().then((ok) => {
      window.__enkoViewsReady = ok;
      try {
        window.dispatchEvent(new CustomEvent("enko-views-ready", { detail: { ok } }));
      } catch (_) {}
      // app.js listens for 'enko-views-ready' (it sets window.__enkoInitDone
      // after running init() once). We don't call enkoInit() directly here
      // to avoid a double-init race.
      // Re-wire theme toggle buttons (any inside views).
      if (window.ui && window.ui.theme && window.ui.theme._wireToggleButtons) {
        window.ui.theme._wireToggleButtons();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap, { once: true });
  } else {
    bootstrap();
  }
})();
