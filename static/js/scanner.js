/* ==========================================================================
   Prompt Inspector — scanner workspace
   ========================================================================== */
(function () {
  "use strict";

  const App = () => window.PIDApp;
  const MAX_FILE_BYTES = 50 * 1024 * 1024;
  const ALLOWED_EXTENSIONS = [".pdf", ".docx", ".txt", ".md", ".markdown", ".text"];

  const state = {
    mode: "text",
    file: null,
    scanning: false,
    engines: null,
    maxJudgesTouched: false,
  };

  const els = {};

  function $(selector) {
    return document.querySelector(selector);
  }

  function init() {
    els.scanPanel = $("#scanPanel");
    els.tabs = Array.from(document.querySelectorAll(".segment[data-mode]"));
    els.tabList = document.querySelector(".segmented[role='tablist']");
    els.paneText = $("#pane-text");
    els.paneFile = $("#pane-file");
    els.inputMeta = $("#inputMeta");
    els.textInput = $("#textInput");
    els.lineNumbers = $("#lineNumbers");
    els.charCount = $("#charCount");
    els.clearTextBtn = $("#clearTextBtn");
    els.dropzone = $("#dropzone");
    els.fileInput = $("#fileInput");
    els.chooseFileBtn = $("#chooseFileBtn");
    els.fileCard = $("#fileCard");
    els.fileName = $("#fileName");
    els.fileType = $("#fileType");
    els.fileSize = $("#fileSize");
    els.removeFileBtn = $("#removeFileBtn");
    els.fileError = $("#fileError");
    els.scanError = $("#scanError");
    els.scanErrorDetail = $("#scanErrorDetail");
    els.retryScanBtn = $("#retryScanBtn");
    els.scanProgress = $("#scanProgress");
    els.scanProgressText = $("#scanProgressText");
    els.scanProgressNote = $("#scanProgressNote");
    els.provider = $("#provider");
    els.model = $("#model");
    els.maxJudges = $("#maxJudges");
    els.advancedToggle = $("#advancedToggle");
    els.advancedPanel = $("#advancedPanel");
    els.judgeAll = $("#judgeAll");
    els.analyzeBtn = $("#analyzeBtn");
    els.analyzeLabel = $("#analyzeLabel");

    bindTabs();
    bindEditor();
    bindUpload();
    bindConfiguration();
    bindActions();
    updateEditorStats();
    setMode("text");
    updateAnalyzeState();
  }

  function bindTabs() {
    els.tabs.forEach((tab) => {
      tab.addEventListener("click", () => setMode(tab.dataset.mode));
    });

    if (els.tabList) {
      els.tabList.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
        event.preventDefault();
        const current = state.mode === "text" ? 0 : 1;
        const next = event.key === "ArrowRight"
          ? (current + 1) % els.tabs.length
          : (current - 1 + els.tabs.length) % els.tabs.length;
        els.tabs[next].focus();
        setMode(els.tabs[next].dataset.mode);
      });
    }
  }

  function setMode(mode) {
    state.mode = mode === "file" ? "file" : "text";
    els.tabs.forEach((tab) => {
      const active = tab.dataset.mode === state.mode;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.tabIndex = active ? 0 : -1;
    });
    if (els.paneText) els.paneText.hidden = state.mode !== "text";
    if (els.paneFile) els.paneFile.hidden = state.mode !== "file";
    if (els.inputMeta) {
      els.inputMeta.textContent = state.mode === "text"
        ? "Text · UTF-8 · sent only when you analyze"
        : "Document · PDF, DOCX, TXT, MD · max 50 MB";
    }
    clearScanError();
    updateAnalyzeState();
  }

  function bindEditor() {
    if (els.textInput) {
      els.textInput.addEventListener("input", () => {
        updateEditorStats();
        clearScanError();
        updateAnalyzeState();
      });
      els.textInput.addEventListener("scroll", syncLineScroll);
    }
    if (els.clearTextBtn) {
      els.clearTextBtn.addEventListener("click", () => {
        if (!els.textInput) return;
        els.textInput.value = "";
        updateEditorStats();
        clearScanError();
        updateAnalyzeState();
        els.textInput.focus();
      });
    }
  }

  function updateEditorStats() {
    if (!els.textInput) return;
    const value = els.textInput.value;
    const length = value.length;
    const lines = value ? value.split("\n").length : 1;
    if (els.charCount) {
      els.charCount.textContent = length.toLocaleString() + " character" +
        (length === 1 ? "" : "s") + " · " + lines.toLocaleString() +
        " line" + (lines === 1 ? "" : "s");
    }
    if (els.lineNumbers) {
      const count = Math.max(1, Math.min(lines, 5000));
      const numbers = [];
      for (let i = 1; i <= count; i += 1) numbers.push(i);
      els.lineNumbers.textContent = numbers.join("\n");
      syncLineScroll();
    }
  }

  function syncLineScroll() {
    if (!els.lineNumbers || !els.textInput) return;
    els.lineNumbers.scrollTop = els.textInput.scrollTop;
  }

  function bindUpload() {
    if (els.dropzone) {
      els.dropzone.addEventListener("click", (event) => {
        if (event.target.closest("#chooseFileBtn")) return;
        if (els.fileInput) els.fileInput.click();
      });
      els.dropzone.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        if (els.fileInput) els.fileInput.click();
      });
      ["dragenter", "dragover"].forEach((name) => {
        els.dropzone.addEventListener(name, (event) => {
          event.preventDefault();
          event.stopPropagation();
          els.dropzone.classList.add("is-dragover");
        });
      });
      ["dragleave", "drop"].forEach((name) => {
        els.dropzone.addEventListener(name, (event) => {
          event.preventDefault();
          event.stopPropagation();
          if (name === "dragleave" && event.relatedTarget &&
              els.dropzone.contains(event.relatedTarget)) return;
          els.dropzone.classList.remove("is-dragover");
        });
      });
      els.dropzone.addEventListener("drop", (event) => {
        const file = event.dataTransfer && event.dataTransfer.files
          ? event.dataTransfer.files[0]
          : null;
        if (file) selectFile(file);
      });
    }

    if (els.chooseFileBtn) {
      els.chooseFileBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        if (els.fileInput) els.fileInput.click();
      });
    }

    if (els.fileInput) {
      els.fileInput.addEventListener("change", () => {
        const file = els.fileInput.files && els.fileInput.files[0];
        if (file) selectFile(file);
      });
    }

    if (els.removeFileBtn) {
      els.removeFileBtn.addEventListener("click", clearFile);
    }
  }

  function selectFile(file) {
    clearFileError();
    const name = file && file.name ? file.name : "Selected file";
    const dot = name.lastIndexOf(".");
    const ext = dot >= 0 ? name.slice(dot).toLowerCase() : "";

    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      state.file = null;
      showFileError("Unsupported file type" + (ext ? " “" + ext + "”" : "") +
        ". Choose a PDF, DOCX, TXT, MD, MARKDOWN, or TEXT file.");
      updateFileCard();
      updateAnalyzeState();
      return;
    }

    if (Number(file.size) > MAX_FILE_BYTES) {
      state.file = null;
      showFileError("This file is " + App().formatBytes(file.size) +
        ". The maximum supported size is 50 MB.");
      updateFileCard();
      updateAnalyzeState();
      return;
    }

    state.file = file;
    clearScanError();
    updateFileCard();
    updateAnalyzeState();
  }

  function updateFileCard() {
    if (!els.fileCard || !els.fileName || !els.fileType || !els.fileSize) return;
    if (!state.file) {
      els.fileCard.hidden = true;
      return;
    }
    const ext = state.file.name.slice(state.file.name.lastIndexOf(".")).toLowerCase();
    els.fileName.textContent = state.file.name;
    els.fileType.textContent = ext.slice(1).toUpperCase() +
      (state.file.type ? " · " + state.file.type : "");
    els.fileSize.textContent = App().formatBytes(state.file.size);
    els.fileCard.hidden = false;
  }

  function clearFile() {
    state.file = null;
    if (els.fileInput) els.fileInput.value = "";
    clearFileError();
    clearScanError();
    updateFileCard();
    updateAnalyzeState();
  }

  function showFileError(message) {
    if (!els.fileError) return;
    els.fileError.textContent = message;
    els.fileError.hidden = false;
  }

  function clearFileError() {
    if (!els.fileError) return;
    els.fileError.textContent = "";
    els.fileError.hidden = true;
  }

  function bindConfiguration() {
    if (els.provider) {
      els.provider.addEventListener("change", () => {
        updateModelPlaceholder();
        updateJudgeControls();
      });
    }
    if (els.maxJudges) {
      els.maxJudges.addEventListener("input", () => {
        state.maxJudgesTouched = true;
      });
    }
    if (els.advancedToggle) {
      els.advancedToggle.addEventListener("click", () => {
        if (!els.advancedPanel) return;
        const open = els.advancedPanel.hidden;
        els.advancedPanel.hidden = !open;
        els.advancedToggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }
  }

  function bindActions() {
    if (els.analyzeBtn) els.analyzeBtn.addEventListener("click", startScan);
    if (els.retryScanBtn) els.retryScanBtn.addEventListener("click", startScan);

    document.addEventListener("keydown", (event) => {
      if (!(event.metaKey || event.ctrlKey) || event.key !== "Enter") return;
      const app = App();
      if (!app || app.state.view !== "scanner") return;
      if (state.scanning) return;
      event.preventDefault();
      startScan();
    });
  }

  function setEngines(engines) {
    state.engines = engines || null;
    const app = App();
    if (app) app.updateEngineSummary(engines);

    const serverProviders = (engines && engines.scanner_providers) || [];
    if (els.provider && serverProviders.length) {
      const selected = els.provider.value || "auto";
      const known = new Set(serverProviders.map((p) => p.id));
      const fallbackIds = ["auto", "gemini", "offline", "ollama-cloud"];
      const ids = Array.from(new Set(serverProviders.map((p) => p.id).concat(fallbackIds)));
      els.provider.innerHTML = "";

      ids.forEach((id) => {
        if (!known.has(id) && id !== "auto" && id !== "offline") return;
        const item = serverProviders.find((p) => p.id === id) || {};
        const option = document.createElement("option");
        option.value = id;
        let label = item.label || id;
        if (id === "auto") {
          label = "Auto · Gemini → offline → Ollama Cloud";
        } else if (id === "gemini" && !item.configured) {
          label = "Gemini · not configured";
        } else if (id === "ollama-cloud" && !item.configured) {
          label = "Ollama Cloud · not configured";
        }
        option.textContent = label;
        if ((id === "gemini" || id === "ollama-cloud") && !item.configured) {
          option.disabled = true;
        }
        option.selected = id === selected;
        els.provider.appendChild(option);
      });

      const selectedOption = els.provider.selectedOptions
        && els.provider.selectedOptions[0];
      if (!els.provider.value || (selectedOption && selectedOption.disabled)) {
        els.provider.value = "auto";
      }
    }

    if (engines && Number.isFinite(Number(engines.max_judges)) &&
        !state.maxJudgesTouched && els.maxJudges) {
      els.maxJudges.value = String(engines.max_judges);
    }

    updateModelPlaceholder();
    updateJudgeControls();
  }

  function providerInfo(id) {
    const providers = (state.engines && state.engines.providers) || [];
    return providers.find((p) => p.id === id) || null;
  }

  function defaultMaxJudges() {
    const configured = state.engines && Number(state.engines.max_judges);
    if (!Number.isFinite(configured)) return 8;
    return Math.max(0, Math.min(50, Math.trunc(configured)));
  }

  function updateModelPlaceholder() {
    if (!els.model) return;
    const provider = els.provider ? els.provider.value : "auto";
    const gemini = providerInfo("gemini");
    const cloud = providerInfo("ollama_cloud");

    if (provider === "offline") {
      els.model.value = "";
      els.model.placeholder = "Not used for offline detection";
      els.model.disabled = true;
      return;
    }

    els.model.disabled = false;
    if (provider === "gemini") {
      els.model.placeholder = gemini && gemini.model
        ? gemini.model
        : "Provider default";
    } else if (provider === "ollama-cloud") {
      els.model.placeholder = cloud && cloud.model
        ? cloud.model
        : "Provider default";
    } else if (gemini && gemini.configured) {
      els.model.placeholder = "Gemini: " + (gemini.model || "default");
    } else if (cloud && cloud.configured) {
      els.model.placeholder = "Cloud: " + (cloud.model || "default");
    } else {
      els.model.placeholder = "Offline · no judge model";
    }
  }

  function updateJudgeControls() {
    const provider = els.provider ? els.provider.value : "auto";
    const offline = provider === "offline";
    if (els.maxJudges) els.maxJudges.disabled = offline;
    if (els.judgeAll) els.judgeAll.disabled = offline;
    if (els.judgeAll) {
      const row = els.judgeAll.closest(".checkbox-row");
      if (row) row.style.opacity = offline ? "0.55" : "1";
    }
  }

  function updateAnalyzeState() {
    const app = App();
    const hasContent = state.mode === "text"
      ? Boolean(els.textInput && els.textInput.value.trim())
      : Boolean(state.file);
    if (els.analyzeBtn) els.analyzeBtn.disabled = state.scanning || !hasContent;

    if (!state.scanning && els.analyzeLabel) {
      els.analyzeLabel.textContent = state.mode === "text"
        ? "Analyze text"
        : "Analyze document";
    }
    if (app && app.state.view === "scanner" && !state.scanning) {
      // no-op: keeps the editor/button state deterministic
    }
  }

  function showScanError(message) {
    if (!els.scanError || !els.scanErrorDetail) return;
    els.scanErrorDetail.textContent = message || "The backend returned an unknown error.";
    els.scanError.hidden = false;
    window.requestAnimationFrame(() => {
      els.scanError.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }

  function clearScanError() {
    if (!els.scanError) return;
    els.scanError.hidden = true;
    if (els.scanErrorDetail) els.scanErrorDetail.textContent = "";
  }

  function setScanning(value) {
    state.scanning = value;
    if (els.analyzeBtn) {
      els.analyzeBtn.disabled = value || !(state.mode === "text"
        ? els.textInput && els.textInput.value.trim()
        : state.file);
      els.analyzeBtn.setAttribute("aria-busy", value ? "true" : "false");
    }
    if (els.analyzeLabel) {
      els.analyzeLabel.textContent = value
        ? "Analyzing…"
        : state.mode === "text" ? "Analyze text" : "Analyze document";
    }
    if (els.scanPanel) {
      if (value) els.scanPanel.setAttribute("aria-busy", "true");
      else els.scanPanel.removeAttribute("aria-busy");
    }
  }

  async function startScan() {
    if (state.scanning) return;
    const app = App();
    if (!app) return;

    if (state.mode === "text" && (!els.textInput || !els.textInput.value.trim())) {
      showScanError("Enter or paste some text before starting the analysis.");
      if (els.textInput) els.textInput.focus();
      return;
    }
    if (state.mode === "file" && !state.file) {
      showScanError("Choose a document before starting the analysis.");
      return;
    }

    clearScanError();
    if (app.resetResults) app.resetResults();
    const provider = els.provider ? els.provider.value : "auto";
    const model = els.model ? els.model.value.trim() : "";
    const maxJudgesRaw = els.maxJudges && els.maxJudges.value !== ""
      ? Number(els.maxJudges.value)
      : defaultMaxJudges();
    const maxJudges = Number.isFinite(maxJudgesRaw)
      ? Math.max(0, Math.min(50, Math.trunc(maxJudgesRaw)))
      : defaultMaxJudges();
    const judgeAll = Boolean(els.judgeAll && els.judgeAll.checked);
    const startedAt = new Date().toISOString();
    const startedClock = performance.now();
    const sourceName = state.mode === "text" ? "Pasted text" : state.file.name;

    setScanning(true);
    if (els.scanProgress) els.scanProgress.hidden = false;
    if (els.scanProgressText) {
      els.scanProgressText.textContent = "Running offline and semantic detection layers…";
    }
    if (els.scanProgressNote) {
      els.scanProgressNote.textContent = "The backend does not expose per-layer progress.";
    }

    try {
      let response;
      if (state.mode === "text") {
        response = await fetch("/scan/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: els.textInput.value,
            provider: provider,
            model: model || null,
            max_judges: maxJudges,
            judge_all: judgeAll,
          }),
        });
      } else {
        const form = new FormData();
        form.append("file", state.file, state.file.name);
        form.append("provider", provider);
        if (model) form.append("model", model);
        form.append("max_judges", String(maxJudges));
        form.append("judge_all", judgeAll ? "true" : "false");
        response = await fetch("/scan/file", { method: "POST", body: form });
      }

      const raw = await response.text();
      let payload = null;
      try {
        payload = raw ? JSON.parse(raw) : null;
      } catch (error) {
        payload = null;
      }

      if (!response.ok) {
        const detail = payload && payload.error
          ? payload.error
          : (raw || "Request failed with HTTP " + response.status).slice(0, 500);
        throw new Error(detail);
      }
      if (!payload) {
        throw new Error("The server returned an empty or non-JSON response.");
      }
      if (payload.error) {
        throw new Error(payload.error);
      }

      if (window.PIDResults) {
        window.PIDResults.render(payload, {
          startedAt: startedAt,
          clientDurationMs: Math.round(performance.now() - startedClock),
          sourceName: sourceName,
          mode: state.mode,
          provider: provider,
        });
      }
      app.showResults();
    } catch (error) {
      const message = error && error.message ? error.message : String(error);
      showScanError(message);
      app.toast("Analysis failed", "error");
    } finally {
      setScanning(false);
      if (els.scanProgress) els.scanProgress.hidden = true;
      updateAnalyzeState();
    }
  }

  function resetAll() {
    state.mode = "text";
    state.file = null;
    state.scanning = false;
    if (els.textInput) els.textInput.value = "";
    if (els.fileInput) els.fileInput.value = "";
    if (els.fileCard) els.fileCard.hidden = true;
    if (els.provider) els.provider.value = "auto";
    if (els.model) {
      els.model.value = "";
      els.model.disabled = false;
    }
    if (els.maxJudges) els.maxJudges.value = String(defaultMaxJudges());
    state.maxJudgesTouched = false;
    if (els.judgeAll) els.judgeAll.checked = false;
    if (els.advancedPanel) els.advancedPanel.hidden = true;
    if (els.advancedToggle) els.advancedToggle.setAttribute("aria-expanded", "false");
    clearFileError();
    clearScanError();
    if (els.scanProgress) els.scanProgress.hidden = true;
    updateEditorStats();
    setMode("text");
    setScanning(false);
    updateModelPlaceholder();
    updateJudgeControls();
    if (els.textInput) els.textInput.focus();
  }

  window.PIDScanner = {
    init,
    setEngines,
    resetAll,
    startScan,
  };
})();
