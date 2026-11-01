/* ==========================================================================
   Prompt Inspector — shell, navigation, shared utilities
   ========================================================================== */
(function () {
  "use strict";

  const state = {
    view: "scanner",
    engines: null,
    resultsVisible: false,
  };

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

  const els = {};

  function cacheElements() {
    els.sidebar = $("#sidebar");
    els.sidebarScrim = $("#sidebarScrim");
    els.menuBtn = $("#menuBtn");
    els.navItems = $$(".nav-item");
    els.views = {
      scanner: $("#view-scanner"),
      engines: $("#view-engines"),
    };
    els.crumb = $("#currentCrumb");
    els.newScanBtn = $("#newScanBtn");
    els.resultsRoot = $("#resultsRoot");
    els.engineChip = $("#engineChip");
    els.engineChipDot = $("#engineChipDot");
    els.engineChipText = $("#engineChipText");
    els.sidebarJudgeDot = $("#sidebarJudgeDot");
    els.sidebarJudgeValue = $("#sidebarJudgeValue");
    els.sidebarJudgeRow = $("#sidebarJudgeRow");
    els.toastRegion = $("#toastRegion");
  }

  function init() {
    cacheElements();
    bindNavigation();
    bindSidebar();
    bindGlobalActions();
    bindEvidenceDrawer();
    bindKeyboard();

    const requested = (location.hash || "").replace("#", "");
    showView(requested === "engines" ? "engines" : "scanner", false);

    if (window.PIDResults) window.PIDResults.init();
    if (window.PIDScanner) window.PIDScanner.init();
    if (window.PIDEngines) window.PIDEngines.init();
  }

  function showView(name, scroll) {
    const view = name === "engines" ? "engines" : "scanner";
    state.view = view;

    Object.entries(els.views).forEach(([key, node]) => {
      if (node) node.hidden = key !== view;
    });

    els.navItems.forEach((item) => {
      const active = item.dataset.view === view;
      if (active) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });

    if (els.crumb) els.crumb.textContent = view === "engines" ? "Engine status" : "Scanner";
    document.title = view === "engines"
      ? "Engine status — Prompt Warden"
      : "Prompt Warden — LLM01 security";

    if (view === "engines") closeEvidence();
    closeSidebar();

    const nextHash = "#" + view;
    if (location.hash !== nextHash) {
      history.replaceState(null, "", nextHash);
    }

    if (scroll !== false) {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function showResults() {
    state.resultsVisible = true;
    if (els.resultsRoot) els.resultsRoot.hidden = false;
    if (els.newScanBtn) els.newScanBtn.hidden = false;
    showView("scanner", false);
    window.requestAnimationFrame(() => {
      if (els.resultsRoot) {
        els.resultsRoot.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  }

  function resetResults() {
    state.resultsVisible = false;
    if (els.resultsRoot) els.resultsRoot.hidden = true;
    if (els.newScanBtn) els.newScanBtn.hidden = true;
    closeEvidence();
    if (window.PIDResults) window.PIDResults.clear();
  }

  function bindNavigation() {
    els.navItems.forEach((item) => {
      item.addEventListener("click", () => showView(item.dataset.view));
    });
  }

  function bindSidebar() {
    if (!els.menuBtn) return;
    els.menuBtn.addEventListener("click", () => {
      if (els.sidebar && els.sidebar.classList.contains("is-open")) closeSidebar();
      else openSidebar();
    });
    if (els.sidebarScrim) {
      els.sidebarScrim.addEventListener("click", closeSidebar);
    }
  }

  function openSidebar() {
    if (!els.sidebar) return;
    els.sidebar.classList.add("is-open");
    document.body.classList.add("has-sidebar");
    if (els.menuBtn) els.menuBtn.setAttribute("aria-expanded", "true");
    if (els.sidebarScrim) els.sidebarScrim.hidden = false;
  }

  function closeSidebar() {
    if (!els.sidebar) return;
    els.sidebar.classList.remove("is-open");
    document.body.classList.remove("has-sidebar");
    if (els.menuBtn) els.menuBtn.setAttribute("aria-expanded", "false");
    if (els.sidebarScrim) els.sidebarScrim.hidden = true;
  }

  function bindGlobalActions() {
    if (els.newScanBtn) {
      els.newScanBtn.addEventListener("click", () => {
        resetResults();
        if (window.PIDScanner) window.PIDScanner.resetAll();
        showView("scanner");
        toast("Workspace cleared", "info");
      });
    }
  }

  function bindEvidenceDrawer() {
    const close = $("#evidenceClose");
    const backdrop = $("#evidenceBackdrop");
    if (close) close.addEventListener("click", closeEvidence);
    if (backdrop) backdrop.addEventListener("click", closeEvidence);
  }

  function openEvidence() {
    if (!window.matchMedia("(max-width: 1180px)").matches) return;
    const panel = $("#evidencePanel");
    const backdrop = $("#evidenceBackdrop");
    if (!panel) return;
    panel.classList.add("is-open");
    document.body.classList.add("has-evidence");
    if (backdrop) {
      backdrop.hidden = false;
      requestAnimationFrame(() => backdrop.classList.add("is-visible"));
    }
    const close = $("#evidenceClose");
    if (close) close.focus({ preventScroll: true });
  }

  function closeEvidence() {
    const panel = $("#evidencePanel");
    const backdrop = $("#evidenceBackdrop");
    if (!panel) return;
    panel.classList.remove("is-open");
    document.body.classList.remove("has-evidence");
    if (backdrop) {
      backdrop.classList.remove("is-visible");
      window.setTimeout(() => {
        if (backdrop && !backdrop.classList.contains("is-visible")) backdrop.hidden = true;
      }, 180);
    }
  }

  function bindKeyboard() {
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeEvidence();
        closeSidebar();
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "1") {
        event.preventDefault();
        showView("scanner");
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "2") {
        event.preventDefault();
        showView("engines");
      }
    });
  }

  /* ----------------------------------------------------------------------
     Engine summary (sidebar + topbar)
     ---------------------------------------------------------------------- */
  function updateEngineSummary(engines) {
    state.engines = engines;
    const providers = (engines && engines.providers) || [];
    const find = (id) => providers.find((p) => p.id === id) || null;
    const gemini = find("gemini");
    const cloud = find("ollama_cloud");

    let text = "Offline only";
    let dotClass = "is-safe";
    let title = "Offline detection is always active.";
    let judgeText = "Offline";
    let judgeDot = "is-safe";

    if (gemini && gemini.configured) {
      if (gemini.reachable === true) {
        text = "Gemini connected";
        dotClass = "is-safe";
        title = "Gemini connectivity was tested successfully. Auto starts with Gemini.";
        judgeText = "Gemini";
        judgeDot = "is-safe";
      } else if (gemini.reachable === false) {
        text = "Gemini unreachable";
        dotClass = "is-danger";
        title = "Gemini is configured but the last connectivity test failed. Auto falls back to offline evidence.";
        judgeText = "Fallback";
        judgeDot = "is-danger";
      } else {
        text = "Gemini configured";
        dotClass = "is-accent";
        title = "Gemini is configured but connectivity has not been tested. Auto may still use it.";
        judgeText = "Gemini";
        judgeDot = "is-accent";
      }
    } else if (cloud && cloud.configured) {
      text = "Ollama Cloud fallback";
      dotClass = "is-accent";
      title = "Gemini is not configured. Ollama Cloud is available as the last-resort judge.";
      judgeText = "Cloud";
      judgeDot = "is-accent";
    }

    if (els.engineChipText) els.engineChipText.textContent = text;
    if (els.engineChip) els.engineChip.title = title;
    if (els.engineChipDot) els.engineChipDot.className = "status-dot " + dotClass;
    if (els.sidebarJudgeValue) els.sidebarJudgeValue.textContent = judgeText;
    if (els.sidebarJudgeDot) els.sidebarJudgeDot.className = "status-dot " + judgeDot;
    if (els.sidebarJudgeRow) els.sidebarJudgeRow.title = title;
  }

  /* ----------------------------------------------------------------------
     Utilities
     ---------------------------------------------------------------------- */
  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function categoryLabel(category) {
    const labels = {
      instruction_override: "Instruction override",
      role_hijack: "Role hijack",
      jailbreak: "Jailbreak",
      prompt_leak: "Prompt leak",
      exfiltration: "Data exfiltration",
      action_abuse: "Tool / action abuse",
      obfuscation: "Obfuscation",
      context_switch: "Context switch",
      token_anomaly: "Token anomaly",
    };
    return labels[category] || String(category || "Rule match").replace(/_/g, " ");
  }

  function severityMeta(level) {
    const key = String(level || "").toUpperCase();
    const map = {
      CLEAN: {
        level: "CLEAN",
        tone: "safe",
        human: "No signals",
        short: "Clean",
        description: "No actionable prompt-injection signals were found by the enabled layers.",
      },
      LOW: {
        level: "LOW",
        tone: "low",
        human: "Low risk",
        short: "Low",
        description: "Weak injection signals were found. Review the flagged segment in context before downstream use.",
      },
      MEDIUM: {
        level: "MEDIUM",
        tone: "medium",
        human: "Suspicious",
        short: "Suspicious",
        description: "Potentially manipulative content was detected. Review the evidence before passing it to a model or tool.",
      },
      HIGH: {
        level: "HIGH",
        tone: "high",
        human: "High risk",
        short: "High",
        description: "Strong injection or exfiltration signals were found. Treat this content as untrusted.",
      },
      CRITICAL: {
        level: "CRITICAL",
        tone: "critical",
        human: "Malicious",
        short: "Critical",
        description: "High-confidence malicious instructions or data-exfiltration behavior were detected.",
      },
    };
    return map[key] || {
      level: key || "UNKNOWN",
      tone: "muted",
      human: "Not assessed",
      short: "Unknown",
      description: "The backend did not return a recognized verdict.",
    };
  }

  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return "Unknown size";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB";
    return (n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0) + " MB";
  }

  function formatDateTime(value) {
    if (!value) return "Unavailable";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unavailable";
    try {
      return new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date);
    } catch (error) {
      return date.toLocaleString();
    }
  }

  function formatDuration(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n < 0) return "Unavailable";
    if (n < 1000) return Math.round(n) + " ms";
    if (n < 60000) return (n / 1000).toFixed(n < 10000 ? 2 : 1) + " s";
    const minutes = Math.floor(n / 60000);
    const seconds = Math.round((n % 60000) / 1000);
    return minutes + "m " + seconds + "s";
  }

  function truncate(value, max) {
    const text = String(value == null ? "" : value);
    if (text.length <= max) return text;
    return text.slice(0, Math.max(0, max - 1)) + "…";
  }

  function highlightSnippets(text, snippets) {
    const source = String(text == null ? "" : text);
    if (!source) return "";
    const ranges = [];
    (snippets || []).forEach((raw) => {
      let needle = String(raw == null ? "" : raw).trim();
      needle = needle.replace(/(?:\.\.\.|…)$/u, "").trim();
      if (needle.length < 4) return;
      let from = 0;
      let hits = 0;
      while (from < source.length && hits < 8) {
        const index = source.indexOf(needle, from);
        if (index < 0) break;
        ranges.push([index, index + needle.length]);
        from = index + needle.length;
        hits += 1;
      }
    });
    if (!ranges.length) return escapeHtml(source);

    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const merged = [];
    ranges.forEach((range) => {
      const last = merged[merged.length - 1];
      if (last && range[0] <= last[1]) {
        last[1] = Math.max(last[1], range[1]);
      } else {
        merged.push(range.slice());
      }
    });

    let html = "";
    let cursor = 0;
    merged.forEach(([start, end]) => {
      if (start > cursor) html += escapeHtml(source.slice(cursor, start));
      html += '<mark class="evidence-mark">' + escapeHtml(source.slice(start, end)) + "</mark>";
      cursor = end;
    });
    if (cursor < source.length) html += escapeHtml(source.slice(cursor));
    return html;
  }

  async function copyText(value, label) {
    const text = String(value == null ? "" : value);
    if (!text) {
      toast("Nothing to copy", "error");
      return false;
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      toast((label || "Copied") + " to clipboard", "success");
      return true;
    } catch (error) {
      toast("Could not copy to clipboard", "error");
      return false;
    }
  }

  function toast(message, tone) {
    if (!els.toastRegion) return;
    const kind = tone === "success" || tone === "error" ? tone : "info";
    const node = document.createElement("div");
    node.className = "toast is-" + kind;
    node.setAttribute("role", kind === "error" ? "alert" : "status");
    const icon = kind === "error" ? "i-alert" : kind === "success" ? "i-check" : "i-info";
    node.innerHTML =
      '<svg aria-hidden="true"><use href="#' + icon + '"></use></svg>' +
      "<span>" + escapeHtml(message) + "</span>";
    els.toastRegion.appendChild(node);
    window.setTimeout(() => {
      node.classList.add("is-leaving");
      window.setTimeout(() => node.remove(), 160);
    }, 3400);
  }

  window.PIDApp = {
    state,
    $,
    $$,
    showView,
    showResults,
    resetResults,
    openEvidence,
    closeEvidence,
    updateEngineSummary,
    severityMeta,
    categoryLabel,
    escapeHtml,
    formatBytes,
    formatDateTime,
    formatDuration,
    truncate,
    highlightSnippets,
    copyText,
    toast,
  };

  document.addEventListener("DOMContentLoaded", init);
})();
