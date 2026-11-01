/* ==========================================================================
   Prompt Inspector — result adapter, findings table, evidence inspector
   ==========================================================================
   The UI reads only fields returned by the detector. Missing fields become an
   explicit unavailable state; the original response is kept for inspection.
   ========================================================================== */
(function () {
  "use strict";

  const App = () => window.PIDApp;

  const state = {
    raw: null,
    meta: null,
    chunks: [],
    findings: [],
    filtered: [],
    levelFilter: "ALL",
    sourceFilter: "ALL",
    selectedIndex: null,
    selectedItem: null,
  };

  const els = {};

  function $(selector) {
    return document.querySelector(selector);
  }

  function numberOrNaN(value) {
    if (value == null || value === "") return NaN;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : NaN;
  }

  function init() {
    els.resultsRoot = $("#resultsRoot");
    els.verdictPanel = $("#verdictPanel");
    els.verdictLabel = $("#verdictLabel");
    els.verdictHuman = $("#verdictHuman");
    els.verdictScore = $("#verdictScore");
    els.verdictDescription = $("#verdictDescription");
    els.verdictMeta = $("#verdictMeta");
    els.analysisSummary = $("#analysisSummary");
    els.layerGrid = $("#layerGrid");
    els.findingsCount = $("#findingsCount");
    els.filterBar = $("#filterBar");
    els.findingsTableWrap = $("#findingsTableWrap");
    els.findingsBody = $("#findingsBody");
    els.findingsEmpty = $("#findingsEmpty");
    els.findingsEmptyTitle = $("#findingsEmptyTitle");
    els.findingsEmptyCopy = $("#findingsEmptyCopy");
    els.evidenceEmpty = $("#evidenceEmpty");
    els.evidenceContent = $("#evidenceContent");
    els.technicalMeta = $("#technicalMeta");
    els.rawJson = $("#rawJson");
    els.copyJsonBtn = $("#copyJsonBtn");
    els.resultsSource = $("#resultsSource");

    bindEvents();
  }

  function bindEvents() {
    if (els.filterBar) {
      els.filterBar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-filter-type]");
        if (!button) return;
        const type = button.dataset.filterType;
        const value = button.dataset.filterValue;
        if (type === "level") state.levelFilter = value;
        if (type === "source") state.sourceFilter = value;
        renderFilters();
        renderFindings();
      });
    }

    if (els.findingsBody) {
      els.findingsBody.addEventListener("click", (event) => {
        const row = event.target.closest("tr[data-index]");
        if (!row) return;
        selectFinding(Number(row.dataset.index), true);
      });
      els.findingsBody.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        const row = event.target.closest("tr[data-index]");
        if (!row) return;
        event.preventDefault();
        selectFinding(Number(row.dataset.index), true);
      });
    }

    if (els.evidenceContent) {
      els.evidenceContent.addEventListener("click", (event) => {
        const button = event.target.closest("[data-copy-evidence]");
        if (!button) return;
        const item = state.selectedItem;
        if (!item) return;
        App().copyText(item.chunk.text || "", "Evidence");
      });
    }

    if (els.copyJsonBtn) {
      els.copyJsonBtn.addEventListener("click", () => {
        if (!state.raw) {
          App().toast("No scan response to copy", "error");
          return;
        }
        App().copyText(JSON.stringify(state.raw, null, 2), "JSON report");
      });
    }
  }

  /* ----------------------------------------------------------------------
     Render
     ---------------------------------------------------------------------- */
  function render(data, meta) {
    state.raw = data;
    state.meta = meta || {};
    state.levelFilter = "ALL";
    state.sourceFilter = "ALL";
    state.selectedIndex = null;
    state.selectedItem = null;

    const chunks = Array.isArray(data && data.chunks) ? data.chunks : [];
    state.chunks = chunks;
    state.findings = chunks
      .map((chunk, index) => ({ chunk, index }))
      .filter((item) => String(item.chunk.level || "").toUpperCase() !== "CLEAN");

    renderVerdict(data, state.meta);
    renderLayers(data, chunks);
    renderFilters();
    renderFindings();
    renderTechnical(data, chunks);
    clearInspector();

    if (state.findings.length) {
      selectFinding(state.findings[0].index, false);
    }
  }

  function renderVerdict(data, meta) {
    const verdict = data && data.verdict ? data.verdict : "UNKNOWN";
    const severity = App().severityMeta(verdict);
    const score = numberOrNaN(data && data.doc_score);
    const nChunks = numberOrNaN(data && data.n_chunks);
    const nFlagged = numberOrNaN(data && data.n_flagged);
    const source = (data && data.source_name) || (data && data.file) || (meta && meta.sourceName) || "Unknown source";
    const requestedProvider = (data && data.requested_provider) || (data && data.provider) || (meta && meta.provider) || "Unknown";
    const judgeLabel = (data && data.judge_label) || "Offline only";
    const startedAt = (data && data.scan_started_at) || (meta && meta.startedAt) || null;
    const backendDuration = numberOrNaN(data && data.scan_duration_ms);
    const clientDuration = numberOrNaN(meta && meta.clientDurationMs);
    const duration = Number.isFinite(backendDuration)
      ? backendDuration
      : (Number.isFinite(clientDuration) ? clientDuration : null);
    const durationSuffix = Number.isFinite(backendDuration) ? "" : " (client)";
    const judgeCalls = numberOrNaN(data && data.judge_calls);
    const cacheHits = numberOrNaN(data && data.cache_hits);
    const fallbackChunks = numberOrNaN(data && data.fallback_chunks);

    if (els.verdictPanel) els.verdictPanel.dataset.tone = severity.tone;
    if (els.verdictLabel) els.verdictLabel.textContent = severity.level;
    if (els.verdictHuman) els.verdictHuman.textContent = severity.human;
    if (els.verdictScore) {
      els.verdictScore.textContent = Number.isFinite(score) ? String(score) : "—";
    }
    if (els.verdictDescription) {
      const countText = Number.isFinite(nChunks)
        ? " " + (Number.isFinite(nFlagged) ? nFlagged : 0) + " of " + nChunks +
          " chunk" + (nChunks === 1 ? "" : "s") + " flagged."
        : "";
      els.verdictDescription.textContent = severity.description + countText;
    }

    const isThreat = severity.level === "CRITICAL" || severity.level === "HIGH";
    const isMedium = severity.level === "MEDIUM";
    const recText = isThreat ? "🚫 Block Ingestion" : isMedium ? "⚠️ Review Required" : "✅ Safe to Ingest";
    const metricRec = $("#metricRecommendation");
    if (metricRec) metricRec.textContent = recText;

    const metricChunks = $("#metricChunks");
    if (metricChunks) {
      metricChunks.textContent = Number.isFinite(nChunks)
        ? nChunks + " scanned (" + (nFlagged || 0) + " flagged)"
        : "1 scanned";
    }

    const metricMethod = $("#metricMethod");
    if (metricMethod) metricMethod.textContent = judgeLabel || "Multi-Layer Guardrail";

    const metricCategory = $("#metricCategory");
    if (metricCategory) {
      const topCat = (data && data.chunks || [])
        .flatMap((c) => (c.matched || []).map((m) => m.category))[0];
      metricCategory.textContent = topCat
        ? App().categoryLabel(topCat)
        : (isThreat ? "Prompt Injection" : "None (Clean)");
    }

    const countBadge = $("#findingsCountBadge");
    if (countBadge) {
      countBadge.textContent = (nFlagged || 0) + " Threat Flags";
      countBadge.className = "badge " + (isThreat ? "badge-critical" : (isMedium ? "badge-medium" : "badge-safe"));
    }

    const techJson = $("#technicalJson");
    if (techJson) {
      techJson.textContent = JSON.stringify(data, null, 2);
    }
    if (els.resultsSource) {
      els.resultsSource.innerHTML =
        '<span class="status-dot ' + (severity.tone === "safe" ? "is-safe" : "is-warn") +
        '" aria-hidden="true"></span>' +
        App().escapeHtml(App().truncate(source, 54));
      if (data && data.file) els.resultsSource.title = data.file;
    }

    if (!els.verdictMeta) return;
    const items = [
      metaItem("Source", source, true, true),
      metaItem("Requested provider", requestedProvider, true, false),
      metaItem("Semantic judge", judgeLabel, false, false),
      metaItem("Scan started", App().formatDateTime(startedAt), false, false),
      metaItem("Duration", duration == null ? "Unavailable" : App().formatDuration(duration) + durationSuffix, false, false),
      metaItem(
        "Chunks",
        Number.isFinite(nChunks)
          ? nChunks + " total · " + (Number.isFinite(nFlagged) ? nFlagged : 0) + " flagged"
          : "Unavailable",
        false,
        false
      ),
      metaItem(
        "Judge calls",
        Number.isFinite(judgeCalls)
          ? judgeCalls + " · " + (Number.isFinite(cacheHits) ? cacheHits : 0) + " cached"
          : "Unavailable",
        false,
        false
      ),
      metaItem(
        "Offline-scored",
        Number.isFinite(fallbackChunks)
          ? fallbackChunks + " chunk" + (fallbackChunks === 1 ? "" : "s")
          : "Unavailable",
        true,
        false
      ),
    ];
    els.verdictMeta.innerHTML = items.join("");
  }

  function metaItem(label, value, mono, strong) {
    return '<div class="meta-item">' +
      '<div class="meta-label">' + App().escapeHtml(label) + "</div>" +
      '<div class="meta-value' + (mono ? " mono" : "") + (strong ? " is-strong" : "") +
      '" title="' + App().escapeHtml(value == null ? "" : value) + '">' +
      App().escapeHtml(value == null || value === "" ? "Unavailable" : value) +
      "</div></div>";
  }

  function layerCard(code, title, tone, status, metric, sub, tag, isAi) {
    const dot = tone === "safe"
      ? "is-safe"
      : tone === "accent"
        ? "is-accent"
        : tone === "critical"
          ? "is-danger"
          : "is-warn";
    return '<div class="layer-card" data-tone="' + tone + '">' +
      '<div class="layer-head">' +
        '<div class="layer-name"><span class="layer-code">' + code + '</span>' +
          '<span class="layer-title">' + App().escapeHtml(title) + "</span></div>" +
        '<span class="layer-status"><span class="status-dot ' + dot + '" aria-hidden="true"></span>' +
          App().escapeHtml(status) + "</span>" +
      "</div>" +
      '<div class="layer-metric' + (metric === "No signals" ? " is-muted" : "") + '">' +
        App().escapeHtml(metric) + "</div>" +
      '<div class="layer-sub" title="' + App().escapeHtml(sub) + '">' + App().escapeHtml(sub) + "</div>" +
      '<span class="layer-tag' + (isAi ? " is-ai" : "") + '">' + App().escapeHtml(tag) + "</span>" +
    "</div>";
  }

  function renderLayers(data, chunks) {
    const ruleHits = chunks.reduce((sum, chunk) =>
      sum + (Array.isArray(chunk.matched) ? chunk.matched.length : 0), 0);
    const structuralChunks = chunks.filter((chunk) => Number(chunk.structural) > 0);
    const maxStructural = chunks.reduce((max, chunk) =>
      Math.max(max, Number(chunk.structural) || 0), 0);
    const decodedChunks = chunks.filter((chunk) => chunk.decoded);
    const anomalyChunks = chunks.filter((chunk) => Number(chunk.anomalies) > 0);
    const judgeResults = chunks.filter((chunk) => chunk.judge);
    const judgeErrors = judgeResults.filter((chunk) => {
      const value = chunk.judge && chunk.judge.verdict;
      return value === "error" || value === "parse_error" || value === "quota_exceeded";
    });
    const judgeCalls = Number(data && data.judge_calls) || 0;
    const cacheHits = Number(data && data.cache_hits) || 0;
    const judgeRan = judgeCalls > 0 || cacheHits > 0;
    const judgeLabel = String((data && data.layers && data.layers.llm_judge)
      || (data && data.judge_label) || "Unavailable");
    const judgeSkipped = !judgeRan && /disabled|offline only|skipped|not configured/i.test(judgeLabel);
    const judgeStatus = judgeErrors.length
      ? "Error"
      : judgeRan
        ? "Ran"
        : judgeSkipped ? "Skipped" : "Not called";

    if (els.layerGrid) {
      const cards = [
        layerCard(
          "L1", "Rules",
          ruleHits ? "high" : "safe",
          ruleHits ? "Detected" : "Clear",
          ruleHits ? ruleHits + " rule hit" + (ruleHits === 1 ? "" : "s") : "No signals",
          ruleHits ? "Deterministic pattern + lexical scoring" : "No rule pattern matched",
          "Offline",
          false
        ),
        layerCard(
          "L2", "Structural",
          structuralChunks.length ? "medium" : "safe",
          structuralChunks.length ? "Detected" : "Clear",
          structuralChunks.length
            ? structuralChunks.length + " chunk" + (structuralChunks.length === 1 ? "" : "s")
            : "No signals",
          structuralChunks.length
            ? "Max weight +" + maxStructural
            : "No hidden text, metadata, or annotation signals",
          "Offline",
          false
        ),
        layerCard(
          "L2.5", "Decode / entropy",
          (decodedChunks.length || anomalyChunks.length) ? "medium" : "safe",
          (decodedChunks.length || anomalyChunks.length) ? "Detected" : "Clear",
          decodedChunks.length || anomalyChunks.length
            ? decodedChunks.length + " decoded · " + anomalyChunks.length + " anomal" + (anomalyChunks.length === 1 ? "y" : "ies")
            : "No signals",
          "Base64 · hex · URL · HTML · ROT13 · token entropy",
          "Offline",
          false
        ),
        layerCard(
          "L3", "AI judge",
          judgeErrors.length ? "critical" : judgeRan ? "accent" : "muted",
          judgeStatus,
          judgeRan
            ? judgeCalls + " call" + (judgeCalls === 1 ? "" : "s") + " · " + cacheHits + " cached"
            : judgeSkipped ? "Not called" : "No calls",
          judgeLabel,
          "AI judge",
          true
        ),
      ];
      els.layerGrid.innerHTML = cards.join("");
    }

    if (els.analysisSummary) {
      const flagged = numberOrNaN(data && data.n_flagged);
      const total = numberOrNaN(data && data.n_chunks);
      const score = numberOrNaN(data && data.doc_score);
      const summary = [];
      if (Number.isFinite(flagged) && Number.isFinite(total)) {
        summary.push(flagged + " flagged / " + total +
          " chunk" + (total === 1 ? "" : "s"));
      }
      if (data && data.verdict) summary.push(String(data.verdict));
      if (Number.isFinite(score)) summary.push("risk " + score + "/100");
      els.analysisSummary.textContent = summary.length ? summary.join(" · ") : "No layer summary returned";
    }
  }

  /* ----------------------------------------------------------------------
     Findings table
     ---------------------------------------------------------------------- */
  function findingCounts() {
    const counts = { ALL: state.findings.length };
    state.findings.forEach((item) => {
      const level = String(item.chunk.level || "").toUpperCase();
      counts[level] = (counts[level] || 0) + 1;
    });
    return counts;
  }

  function sourceCounts() {
    const counts = { rules: 0, structural: 0, judge: 0, decoded: 0 };
    state.findings.forEach((item) => {
      const chunk = item.chunk;
      if (Array.isArray(chunk.matched) && chunk.matched.length) counts.rules += 1;
      if (Number(chunk.structural) > 0) counts.structural += 1;
      if (chunk.judge) counts.judge += 1;
      if (chunk.decoded) counts.decoded += 1;
    });
    return counts;
  }

  function filterButton(type, value, label, count, active) {
    return '<button class="filter-btn' + (active ? " is-active" : "") + '" type="button" ' +
      'data-filter-type="' + type + '" data-filter-value="' + App().escapeHtml(value) + '" ' +
      'aria-pressed="' + (active ? "true" : "false") + '">' +
      App().escapeHtml(label) + ' <span class="filter-count">' + count + "</span></button>";
  }

  function renderFilters() {
    if (!els.filterBar) return;
    if (!state.findings.length) {
      els.filterBar.hidden = true;
      els.filterBar.innerHTML = "";
      return;
    }
    els.filterBar.hidden = false;
    const counts = findingCounts();
    const sources = sourceCounts();
    const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].filter((level) => counts[level]);
    const levelButtons = [
      filterButton("level", "ALL", "All", state.findings.length, state.levelFilter === "ALL"),
    ].concat(levels.map((level) =>
      filterButton("level", level, level, counts[level], state.levelFilter === level)
    ));
    const sourceButtons = [
      filterButton("source", "ALL", "Any source", state.findings.length, state.sourceFilter === "ALL"),
    ];
    [["rules", "Rules"], ["structural", "Structural"], ["judge", "Judge"], ["decoded", "Decoded"]]
      .forEach(([key, label]) => {
        if (sources[key]) {
          sourceButtons.push(filterButton("source", key, label, sources[key], state.sourceFilter === key));
        }
      });

    els.filterBar.innerHTML =
      '<div class="filter-group"><span class="filter-label">Severity</span>' + levelButtons.join("") + "</div>" +
      '<div class="filter-group"><span class="filter-label">Source</span>' + sourceButtons.join("") + "</div>";
  }

  function matchesSource(chunk, source) {
    if (source === "ALL") return true;
    if (source === "rules") return Boolean(chunk.matched && chunk.matched.length);
    if (source === "structural") return Number(chunk.structural) > 0;
    if (source === "judge") return Boolean(chunk.judge);
    if (source === "decoded") return Boolean(chunk.decoded);
    return true;
  }

  function filteredFindings() {
    return state.findings.filter((item) => {
      const level = String(item.chunk.level || "").toUpperCase();
      return (state.levelFilter === "ALL" || state.levelFilter === level) &&
        matchesSource(item.chunk, state.sourceFilter);
    });
  }

  function uniqueCategories(chunk) {
    const seen = new Set();
    const result = [];
    (Array.isArray(chunk.matched) ? chunk.matched : []).forEach((match) => {
      if (!seen.has(match.category)) {
        seen.add(match.category);
        result.push(match.category);
      }
    });
    return result;
  }

  function findingTitle(chunk) {
    const categories = uniqueCategories(chunk);
    if (categories.length) {
      const shown = categories.slice(0, 2).map((category) => App().categoryLabel(category));
      if (categories.length > 2) shown.push("+" + (categories.length - 2));
      return shown.join(" · ");
    }
    const judge = chunk.judge && chunk.judge.verdict;
    if (judge === "injection") return "Semantic injection";
    if (judge === "suspicious") return "Semantically suspicious";
    if (judge === "error" || judge === "parse_error" || judge === "quota_exceeded") {
      return "Judge assessment error";
    }
    if (Number(chunk.structural) > 0) return "Structural anomaly";
    if (chunk.decoded) return "Decoded payload";
    if (chunk.scored_by === "llm") return "Semantic assessment";
    return "Lexical anomaly";
  }

  function findingSubtitle(chunk) {
    const categories = uniqueCategories(chunk);
    const parts = [];
    if (categories.length) parts.push(categories.join(" · "));
    if (chunk.judge_engine) parts.push(chunk.judge_engine);
    if (chunk.scored_by) parts.push("scored by " + chunk.scored_by);
    return parts.join(" · ") || "Aggregate scoring";
  }

  function sourceBadges(chunk) {
    const badges = [];
    if (chunk.matched && chunk.matched.length) {
      badges.push('<span class="badge source-badge is-rules">Rules</span>');
    }
    if (Number(chunk.structural) > 0) {
      badges.push('<span class="badge source-badge is-structural">Structural</span>');
    }
    if (chunk.decoded) {
      badges.push('<span class="badge source-badge is-decoded">Decoded</span>');
    }
    if (chunk.judge) {
      const verdict = chunk.judge.verdict;
      const isError = verdict === "error" || verdict === "parse_error" || verdict === "quota_exceeded";
      badges.push('<span class="badge source-badge is-judge' + (isError ? " is-warn" : "") +
        '" title="' + App().escapeHtml(verdict || "judge") + '">Judge</span>');
    }
    return badges.length ? badges.join("") : '<span class="badge is-neutral">Score</span>';
  }

  function evidenceSummary(chunk) {
    const first = chunk.matched && chunk.matched.length ? chunk.matched[0].snippet : "";
    if (first) return first;
    if (chunk.judge && chunk.judge.reason) return chunk.judge.reason;
    if (Number(chunk.structural) > 0) {
      return "Structural signal · weight +" + chunk.structural;
    }
    if (chunk.decoded) return "Decoded content" + (chunk.decode_kind ? " · " + chunk.decode_kind : "");
    return "Flagged by aggregate score";
  }

  function renderFindings() {
    if (!els.findingsBody) return;
    const filtered = filteredFindings();
    state.filtered = filtered;

    if (els.findingsCount) {
      if (state.findings.length) {
        const filterNote = filtered.length === state.findings.length
          ? ""
          : " · " + filtered.length + " shown";
        els.findingsCount.textContent = state.findings.length + " flagged · " +
          state.chunks.length + " chunk" + (state.chunks.length === 1 ? "" : "s") + filterNote;
      } else {
        els.findingsCount.textContent = state.chunks.length + " chunk" +
          (state.chunks.length === 1 ? "" : "s") + " inspected · no flagged chunks";
      }
    }

    els.findingsBody.innerHTML = filtered.map((item) => {
      const chunk = item.chunk;
      const severity = App().severityMeta(chunk.level);
      const title = findingTitle(chunk);
      const subtitle = findingSubtitle(chunk);
      const evidence = evidenceSummary(chunk);
      const source = chunk.source || "Unknown location";
      const score = Number.isFinite(Number(chunk.score)) ? chunk.score : "—";
      return '<tr data-index="' + item.index + '" tabindex="0" ' +
        'aria-label="' + App().escapeHtml(severity.level + " finding: " + title + ", " + source) + '"' +
        (state.selectedIndex === item.index ? ' class="is-selected"' : "") + ">" +
        '<td><span class="severity-badge" data-tone="' + severity.tone + '">' +
          App().escapeHtml(severity.level) + "</span></td>" +
        '<td><div class="finding-title">' + App().escapeHtml(title) + "</div>" +
          '<div class="finding-subtitle" title="' + App().escapeHtml(subtitle) + '">' +
          App().escapeHtml(subtitle) + "</div></td>" +
        '<td><div class="source-list">' + sourceBadges(chunk) + "</div></td>" +
        '<td><div class="finding-evidence" title="' + App().escapeHtml(evidence) + '">' +
          App().escapeHtml(evidence) + "</div></td>" +
        '<td><div class="finding-location" title="' + App().escapeHtml(source) + '">' +
          App().escapeHtml(source) + "</div></td>" +
        '<td><div class="finding-score">' + App().escapeHtml(score) + "</div></td>" +
        "</tr>";
    }).join("");

    if (els.findingsTableWrap) {
      els.findingsTableWrap.hidden = filtered.length === 0;
    }

    const findingsList = $("#findingsList");
    if (findingsList) {
      if (filtered.length === 0) {
        findingsList.innerHTML = "";
      } else {
        findingsList.innerHTML = filtered.map((item) => {
          const chunk = item.chunk;
          const sev = App().severityMeta(chunk.level);
          const title = findingTitle(chunk);
          const evidence = evidenceSummary(chunk);
          const source = chunk.source || "Document Body";
          const snippet = (chunk.matched && chunk.matched[0] && chunk.matched[0].snippet) || chunk.text || "";
          return '<div class="finding-card">' +
            '<div class="finding-top">' +
              '<div class="finding-badges">' +
                '<span class="badge badge-' + sev.tone + '">' + App().escapeHtml(sev.level) + '</span>' +
                '<span class="badge-source">' + App().escapeHtml(source) + '</span>' +
                '<span style="font-weight:600;font-size:var(--font-size-sm);color:var(--text);margin-left:4px">' + App().escapeHtml(title) + '</span>' +
              '</div>' +
              '<span class="mono muted" style="font-size:var(--font-size-xs)">Risk Score: ' + (chunk.score || 0) + '/100</span>' +
            '</div>' +
            '<div class="finding-quote">"' + App().escapeHtml(snippet) + '"</div>' +
            '<div class="finding-reason"><strong>Trigger Signal:</strong> ' + App().escapeHtml(evidence) + '</div>' +
          '</div>';
        }).join("");
      }
    }
    if (els.findingsEmpty) {
      const hasFindings = state.findings.length > 0;
      const noMatches = hasFindings && filtered.length === 0;
      els.findingsEmpty.hidden = filtered.length !== 0;
      if (els.findingsEmptyTitle) {
        els.findingsEmptyTitle.textContent = noMatches
          ? "No findings match these filters"
          : "No findings at current thresholds";
      }
      if (els.findingsEmptyCopy) {
        els.findingsEmptyCopy.textContent = noMatches
          ? "Adjust the severity or source filter to inspect the other flagged chunks."
          : "Offline analysis completed without a flagged chunk. Review the technical report for the raw detector response.";
      }
    }
  }

  /* ----------------------------------------------------------------------
     Evidence inspector
     ---------------------------------------------------------------------- */
  function clearInspector() {
    state.selectedIndex = null;
    state.selectedItem = null;
    if (els.evidenceContent) {
      els.evidenceContent.hidden = true;
      els.evidenceContent.innerHTML = "";
    }
    if (els.evidenceEmpty) els.evidenceEmpty.hidden = false;
    if (els.findingsBody) {
      els.findingsBody.querySelectorAll("tr.is-selected").forEach((row) => {
        row.classList.remove("is-selected");
      });
    }
  }

  function selectFinding(index, openDrawer) {
    const item = state.findings.find((entry) => entry.index === index);
    if (!item) return;
    state.selectedIndex = index;
    state.selectedItem = item;
    if (els.findingsBody) {
      els.findingsBody.querySelectorAll("tr[data-index]").forEach((row) => {
        row.classList.toggle("is-selected", Number(row.dataset.index) === index);
      });
    }
    renderInspector(item);
    if (openDrawer && window.PIDApp) window.PIDApp.openEvidence();
  }

  function section(title, content, action) {
    return '<section class="inspector-section">' +
      '<div class="inspector-section-head"><span class="inspector-section-title">' +
        App().escapeHtml(title) + "</span>" + (action || "") + "</div>" +
      content + "</section>";
  }

  function kvRows(rows) {
    return '<div class="kv-list">' + rows.map(([key, value, mono]) =>
      '<div class="kv-row"><span class="kv-key">' + App().escapeHtml(key) + "</span>" +
      '<span class="kv-value' + (mono ? " mono" : "") + '">' +
        App().escapeHtml(value == null || value === "" ? "Unavailable" : value) +
      "</span></div>"
    ).join("") + "</div>";
  }

  function judgeSection(chunk) {
    const judge = chunk.judge;
    if (!judge) {
      return section("AI judge", '<p class="inspector-copy">Not assessed by an LLM. ' +
        "Offline rule, structural, decode, and entropy layers still contributed to this score.</p>");
    }

    const stateClass = judge.verdict === "error" || judge.verdict === "parse_error" ||
      judge.verdict === "quota_exceeded" ? " judge-error" : "";
    const confidence = Number(judge.confidence);
    const confidenceText = Number.isFinite(confidence)
      ? Math.round(confidence * 100) + "%"
      : "Unavailable";
    const detailRows = [
      ["Verdict", judge.verdict || "Unavailable"],
      ["Confidence", confidenceText],
      ["Engine", chunk.judge_engine || judge.engine || "Unavailable"],
      ["Fallback", chunk.judge_fallback_from || judge.fallback_from || "No"],
      ["Cached", judge.cached ? "Yes" : "No"],
    ];
    return section(
      "AI judge",
      '<div class="judge-box">' +
        '<div class="judge-box-head">' +
          '<span class="badge ' + (stateClass ? "is-danger" : "is-primary") + '">' +
            App().escapeHtml(judge.verdict || "unknown") + "</span>" +
          '<span class="section-kicker">Semantic assessment</span>' +
        "</div>" +
        '<div class="judge-reason' + stateClass + '">' +
          App().escapeHtml(judge.reason || "No reason returned by the judge.") + "</div>" +
        '<div class="section-divider"></div>' +
        kvRows(detailRows) +
      "</div>"
    );
  }

  function ruleSection(chunk) {
    const matched = Array.isArray(chunk.matched) ? chunk.matched : [];
    if (!matched.length) {
      return section("Rule evidence", '<p class="inspector-copy muted">No rule snippets were returned for this chunk.</p>');
    }
    const rows = matched.map((match) =>
      '<div class="hit-row">' +
        '<div class="hit-main"><div class="hit-category">' +
          App().escapeHtml(App().categoryLabel(match.category)) +
          '<span class="muted"> · ' + App().escapeHtml(match.category) + "</span></div>" +
          '<div class="hit-snippet">' + App().escapeHtml(match.snippet || "No snippet") + "</div></div>" +
        '<div class="hit-weight">+' + App().escapeHtml(match.weight == null ? "?" : match.weight) + "</div>" +
      "</div>"
    ).join("");
    return section("Rule evidence", '<div class="hit-list">' + rows + "</div>");
  }

  function evidenceSection(chunk) {
    const text = String(chunk.text == null ? "" : chunk.text);
    const snippets = (Array.isArray(chunk.matched) ? chunk.matched : [])
      .map((match) => match.snippet)
      .filter(Boolean);
    const highlighted = text
      ? App().highlightSnippets(text, snippets)
      : '<span class="muted">The backend returned no extracted text for this chunk.</span>';
    const note = chunk.text_truncated
      ? "Preview truncated by the backend at " + (chunk.text_length || text.length) + " characters."
      : "Highlighted spans are exact rule snippets found in the extracted text. The backend does not return source offsets.";
    const meta = [];
    if (chunk.decoded) meta.push("Decoded" + (chunk.decode_kind ? " · " + chunk.decode_kind : ""));
    if (chunk.derived_from) meta.push("Derived from " + chunk.derived_from);
    if (Number(chunk.anomalies) > 0) meta.push(chunk.anomalies + " token anomalies");

    return section(
      "Extracted evidence",
      '<div class="evidence-text-wrap">' +
        '<pre class="evidence-text">' + highlighted + "</pre>" +
        '<div class="evidence-text-note"><span>' + App().escapeHtml(note) + "</span>" +
          '<button class="copy-inline" type="button" data-copy-evidence="true">' +
            '<svg aria-hidden="true"><use href="#i-copy"></use></svg> Copy evidence</button></div>' +
      "</div>" +
      (meta.length ? '<div style="margin-top:7px">' + kvRows(meta.map((item) => ["Provenance", item])) + "</div>" : ""),
      '<span class="section-kicker mono">' + App().escapeHtml(text.length + " chars returned") + "</span>"
    );
  }

  function technicalSection(chunk) {
    return section(
      "Technical identifiers",
      kvRows([
        ["Source", chunk.source || "Unavailable", true],
        ["Chunk score", chunk.score == null ? "Unavailable" : String(chunk.score), true],
        ["Rule score", chunk.rule_score == null ? "Unavailable" : String(chunk.rule_score), true],
        ["Structural", chunk.structural == null ? "Unavailable" : "+" + chunk.structural, true],
        ["Decode kind", chunk.decode_kind || "None", true],
        ["Derived from", chunk.derived_from || "None", true],
        ["Anomalies", chunk.anomalies == null ? "Unavailable" : String(chunk.anomalies), true],
        ["Scored by", chunk.scored_by || "Unavailable", true],
        ["Judge engine", chunk.judge_engine || "None", true],
      ])
    );
  }

  function guidance(chunk) {
    const level = String(chunk.level || "").toUpperCase();
    let text;
    if (level === "CRITICAL" || level === "HIGH") {
      text = "Quarantine this content and isolate the flagged segment before it reaches an LLM, retrieval index, or tool. Review the source document before any downstream ingestion.";
    } else if (level === "MEDIUM") {
      text = "Review this segment in context before passing the document to a model. Do not let it trigger tools or actions without validation.";
    } else if (level === "LOW") {
      text = "No automatic action is required. Review the flagged segment before downstream ingestion and verify the source is trusted.";
    } else {
      text = "No action is required for this chunk.";
    }
    return '<div class="guidance' + (level === "CLEAN" ? " is-safe" : "") + '">' +
      App().escapeHtml(text) + "</div>";
  }

  function renderInspector(item) {
    if (!els.evidenceContent) return;
    const chunk = item.chunk;
    const severity = App().severityMeta(chunk.level);
    const title = findingTitle(chunk);
    const source = chunk.source || "Unknown location";
    const score = chunk.score == null ? "—" : chunk.score;
    const ruleScore = chunk.rule_score == null ? "—" : chunk.rule_score;
    const categories = uniqueCategories(chunk);
    const summaryParts = [];
    if (categories.length) {
      summaryParts.push("Rules matched " + categories.map((category) => App().categoryLabel(category)).join(", ") + ".");
    }
    if (Number(chunk.structural) > 0) {
      summaryParts.push("Structural forensics assigned weight +" + chunk.structural + ".");
    }
    if (chunk.decoded) {
      summaryParts.push("This chunk was decoded from " + (chunk.decode_kind || "an encoded stream") +
        (chunk.derived_from ? " derived from " + chunk.derived_from : "") + ".");
    }
    if (Number(chunk.anomalies) > 0) {
      summaryParts.push(chunk.anomalies + " token anomalies were detected.");
    }
    if (chunk.judge && ["injection", "suspicious", "benign"].includes(chunk.judge.verdict)) {
      const confidence = Number(chunk.judge.confidence);
      summaryParts.push("The AI judge returned " + chunk.judge.verdict +
        (Number.isFinite(confidence) ? " with confidence " + Math.round(confidence * 100) + "%" : "") + ".");
    } else if (chunk.judge) {
      summaryParts.push("The AI judge returned an operational state: " + chunk.judge.verdict + ".");
    } else {
      summaryParts.push("No semantic judge assessment is attached to this chunk.");
    }

    const header =
      '<header class="inspector-header">' +
        '<div class="inspector-title-row">' +
          '<div><span class="severity-badge" data-tone="' + severity.tone + '">' +
            App().escapeHtml(severity.level) + "</span>" +
            '<div class="inspector-title">' + App().escapeHtml(title) + "</div>" +
            '<div class="inspector-source">' + App().escapeHtml(source) + "</div>" +
          "</div>" +
          '<span class="section-kicker mono">#' + item.index + "</span>" +
        "</div>" +
        '<div class="inspector-scoreline">' +
          '<span class="inspector-score">score ' + App().escapeHtml(score) + "</span>" +
          '<span class="inspector-score">· rule score ' + App().escapeHtml(ruleScore) + "</span>" +
          '<span class="inspector-score">· ' + App().escapeHtml(chunk.scored_by || "unscored") + "</span>" +
        "</div>" +
      "</header>";

    const body =
      section("Why it fired", '<p class="inspector-copy">' +
        App().escapeHtml(summaryParts.join(" ")) + "</p>") +
      ruleSection(chunk) +
      judgeSection(chunk) +
      evidenceSection(chunk) +
      technicalSection(chunk) +
      section("Handling guidance", guidance(chunk));

    els.evidenceContent.innerHTML = header + body;
    els.evidenceContent.hidden = false;
    if (els.evidenceEmpty) els.evidenceEmpty.hidden = true;
  }

  /* ----------------------------------------------------------------------
     Technical report
     ---------------------------------------------------------------------- */
  function renderTechnical(data, chunks) {
    if (els.rawJson) {
      els.rawJson.textContent = JSON.stringify(data, null, 2);
    }
    if (!els.technicalMeta) return;
    const judgeErrors = chunks.filter((chunk) => chunk.judge &&
      ["error", "parse_error", "quota_exceeded"].includes(chunk.judge.verdict)).length;
    const duration = numberOrNaN(data && data.scan_duration_ms);
    const items = [
      metaItem("Source", (data && data.source_name) || (data && data.file) || "Unavailable", true, true),
      metaItem("Requested", (data && data.requested_provider) || (data && data.provider) || "Unavailable", true, false),
      metaItem("Backend provider", (data && data.provider) || "Unavailable", true, false),
      metaItem("Judge label", (data && data.judge_label) || "Offline only", false, false),
      metaItem("Started", App().formatDateTime(data && data.scan_started_at), false, false),
      metaItem("Duration", Number.isFinite(duration)
        ? App().formatDuration(duration) : "Unavailable", false, false),
      metaItem("Chunks", data && data.n_chunks != null ? String(data.n_chunks) : "Unavailable", true, false),
      metaItem("Flagged", data && data.n_flagged != null ? String(data.n_flagged) : "Unavailable", true, false),
      metaItem("Judge calls", data && data.judge_calls != null ? String(data.judge_calls) : "Unavailable", true, false),
      metaItem("Cache hits", data && data.cache_hits != null ? String(data.cache_hits) : "Unavailable", true, false),
      metaItem("Fallback chunks", data && data.fallback_chunks != null ? String(data.fallback_chunks) : "Unavailable", true, false),
      metaItem("Judge errors", String(judgeErrors), true, judgeErrors > 0),
    ];
    els.technicalMeta.innerHTML = items.join("");
  }

  function clear() {
    state.raw = null;
    state.meta = null;
    state.chunks = [];
    state.findings = [];
    state.filtered = [];
    state.levelFilter = "ALL";
    state.sourceFilter = "ALL";
    state.selectedIndex = null;
    state.selectedItem = null;
    if (els.findingsBody) els.findingsBody.innerHTML = "";
    if (els.filterBar) {
      els.filterBar.innerHTML = "";
      els.filterBar.hidden = true;
    }
    if (els.findingsEmpty) els.findingsEmpty.hidden = true;
    if (els.rawJson) els.rawJson.textContent = "";
    if (els.technicalMeta) els.technicalMeta.innerHTML = "";
    clearInspector();
  }

  window.PIDResults = {
    init,
    render,
    clear,
  };
})();
