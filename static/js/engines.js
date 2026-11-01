/* ==========================================================================
   Prompt Inspector — engine status
   ========================================================================== */
(function () {
  "use strict";

  const App = () => window.PIDApp;

  const state = {
    engines: null,
    loading: false,
  };

  const els = {};

  function $(selector) {
    return document.querySelector(selector);
  }

  function init() {
    els.loading = $("#engineLoading");
    els.tableWrap = $("#engineTableWrap");
    els.tableBody = $("#engineTableBody");
    els.lastChecked = $("#engineLastChecked");
    els.probeStatus = $("#probeStatus");
    els.error = $("#engineError");
    els.errorDetail = $("#engineErrorDetail");
    els.refreshBtn = $("#refreshEnginesBtn");
    els.probeBtn = $("#probeEnginesBtn");
    els.policyCopy = $("#policyCopy");
    els.policyChain = $("#policyChain");

    if (els.refreshBtn) els.refreshBtn.addEventListener("click", () => load(false));
    if (els.probeBtn) els.probeBtn.addEventListener("click", () => load(true));
    load(false);
  }

  async function load(probe) {
    if (state.loading) return;
    state.loading = true;
    setButtons(true);
    if (els.error) els.error.hidden = true;
    if (els.probeStatus) {
      els.probeStatus.innerHTML = '<span class="status-dot is-accent" aria-hidden="true"></span>' +
        (probe ? "Testing connections…" : "Reading configuration…");
    }
    if (!state.engines && els.loading) els.loading.hidden = false;

    try {
      const response = await fetch("/engines" + (probe ? "?probe=1" : ""), {
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      const raw = await response.text();
      let data = null;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch (error) {
        data = null;
      }
      if (!response.ok) {
        throw new Error((data && data.error) || raw || "HTTP " + response.status);
      }
      if (!data) throw new Error("The server returned an empty engine response.");

      state.engines = data;
      render(data);
      if (window.PIDScanner) window.PIDScanner.setEngines(data);
      if (window.PIDApp) window.PIDApp.updateEngineSummary(data);
      if (probe) App().toast("Connectivity check completed", "success");
    } catch (error) {
      const message = error && error.message ? error.message : String(error);
      if (els.error) els.error.hidden = false;
      if (els.errorDetail) els.errorDetail.textContent = message;
      if (els.loading) els.loading.hidden = true;
      if (els.tableWrap) els.tableWrap.hidden = true;
      if (window.PIDApp) {
        window.PIDApp.updateEngineSummary({
          providers: [],
          scanner_providers: [],
        });
      }
      App().toast("Engine status unavailable", "error");
    } finally {
      state.loading = false;
      setButtons(false);
      if (els.loading) els.loading.hidden = true;
    }
  }

  function setButtons(disabled) {
    if (els.refreshBtn) els.refreshBtn.disabled = disabled;
    if (els.probeBtn) {
      els.probeBtn.disabled = disabled;
      els.probeBtn.setAttribute("aria-busy", disabled ? "true" : "false");
    }
  }

  function render(data) {
    const policy = data.policy || {};
    if (els.policyCopy) {
      els.policyCopy.textContent = policy.description ||
        "Offline detection always runs. Auto uses Gemini first; offline evidence is the fallback, and Ollama Cloud is the last-resort judge.";
    }
    renderChain((policy.auto_chain || ["gemini", "offline", "ollama_cloud"]));

    if (els.lastChecked) {
      const tested = data.tested_at;
      els.lastChecked.textContent = tested
        ? "Connectivity tested " + App().formatDateTime(tested)
        : "Configuration read " + App().formatDateTime(data.generated_at);
    }
    if (els.probeStatus) {
      const tested = Boolean(data.probe);
      els.probeStatus.innerHTML = '<span class="status-dot ' +
        (tested ? "is-safe" : "is-accent") + '" aria-hidden="true"></span>' +
        (tested ? "Connectivity tested" : "Not tested");
    }

    const providers = Array.isArray(data.providers) ? data.providers : [];
    if (els.tableBody) {
      els.tableBody.innerHTML = providers.map(providerRow).join("");
    }
    if (els.tableWrap) els.tableWrap.hidden = false;
    if (els.loading) els.loading.hidden = true;
    if (els.error) els.error.hidden = true;
  }

  function renderChain(chain) {
    if (!els.policyChain) return;
    const labels = {
      gemini: "Gemini",
      offline: "Offline",
      ollama_cloud: "Ollama Cloud",
    };
    els.policyChain.innerHTML = chain.map((id, index) =>
      (index ? '<span class="chain-arrow" aria-hidden="true">→</span>' : "") +
      '<span class="chain-node' + (index === 0 ? " is-primary" : "") + '">' +
        App().escapeHtml(labels[id] || id) + "</span>"
    ).join("");
  }

  function connectivityBadge(provider) {
    const stateValue = provider.connectivity || "not_tested";
    const map = {
      active: ["is-safe", "Active"],
      reachable: ["is-safe", "Reachable"],
      unreachable: ["is-danger", "Unreachable"],
      not_configured: ["is-neutral", "Not configured"],
      disabled: ["is-neutral", "Disabled"],
      not_tested: ["is-warn", "Not tested"],
    };
    const [className, label] = map[stateValue] || ["is-neutral", "Unknown"];
    return '<span class="badge ' + className + '">' + App().escapeHtml(label) + "</span>";
  }

  function configurationBadge(provider) {
    if (provider.id === "offline") {
      return '<span class="badge is-safe">Always on</span>';
    }
    if (provider.connectivity === "disabled") {
      return '<span class="badge is-neutral">Disabled</span>';
    }
    return provider.configured
      ? '<span class="badge is-primary">Configured</span>'
      : '<span class="badge is-neutral">Not configured</span>';
  }

  function dotClass(provider) {
    if (provider.connectivity === "reachable" || provider.connectivity === "active") return "is-safe";
    if (provider.connectivity === "unreachable") return "is-danger";
    if (provider.configured) return "is-accent";
    return "";
  }

  function roleBadge(provider) {
    const roles = {
      primary: ["is-primary", "Primary"],
      fallback: ["is-safe", "Fallback"],
      last_resort: ["is-warn", "Last resort"],
      disabled: ["is-neutral", "Disabled"],
      optional: ["is-neutral", "Optional"],
    };
    const [className, label] = roles[provider.role] || ["is-neutral", provider.role_label || "Optional"];
    return '<span class="badge ' + className + '">' + App().escapeHtml(label) + "</span>";
  }

  function providerRow(provider) {
    const models = Array.isArray(provider.models) ? provider.models : [];
    const model = provider.model || "Unavailable";
    const modelNote = models.length
      ? models.length + " model" + (models.length === 1 ? "" : "s") + " visible"
      : (provider.kind || "engine");
    const details = provider.details || "No details returned.";
    const error = provider.error
      ? '<div class="engine-error">' + App().escapeHtml(provider.error) + "</div>"
      : "";

    return "<tr>" +
      '<td data-label="Engine">' +
        '<div class="engine-name"><span class="status-dot ' + dotClass(provider) +
          '" aria-hidden="true"></span>' + App().escapeHtml(provider.name || provider.id) + "</div>" +
        '<div class="engine-kind">' + App().escapeHtml(provider.kind || "provider") + "</div>" +
      "</td>" +
      '<td data-label="Role">' + roleBadge(provider) + "</td>" +
      '<td data-label="Configuration">' + configurationBadge(provider) + "</td>" +
      '<td data-label="Connectivity">' + connectivityBadge(provider) + "</td>" +
      '<td data-label="Model"><div class="engine-model" title="' + App().escapeHtml(model) + '">' +
        App().escapeHtml(model) + "</div>" +
        '<div class="engine-kind">' + App().escapeHtml(modelNote) + "</div></td>" +
      '<td data-label="Details"><div class="engine-detail">' + App().escapeHtml(details) + "</div>" + error + "</td>" +
    "</tr>";
  }

  window.PIDEngines = {
    init,
    refresh: () => load(false),
    testConnections: () => load(true),
    get: () => state.engines,
  };
})();
