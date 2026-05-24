const API = { events: "/api/events", analyses: "/api/analyses", analyze: "/api/analyze", remediations: "/api/remediations", remediate: "/api/remediate", orchestrate: "/api/orchestrate" };
let eventsData = [];
let analysesData = [];
let selectedAnalysisId = null;
let orchestrationSessionId = null;
let orchestrationPollTimer = null;
let dataRefreshTimer = null;
let hasEverHadData = false;

async function getJSON(url, opts = {}) {
  const r = await fetch(url, { headers: { "Content-Type": "application/json" }, ...opts });
  return r.json();
}

function showSections() {
  document.getElementById("stats-row").classList.remove("section-hidden");
  document.getElementById("grid-2").classList.remove("section-hidden");
}

function hideSections() {
  document.getElementById("stats-row").classList.add("section-hidden");
  document.getElementById("grid-2").classList.add("section-hidden");
}

function startDataRefresh() {
  if (dataRefreshTimer) clearInterval(dataRefreshTimer);
  dataRefreshTimer = setInterval(async () => {
    if (orchestrationPollTimer) return;
    await refreshEvents();
    await refreshAnalyses();
  }, 15000);
}

function stopDataRefresh() {
  if (dataRefreshTimer) {
    clearInterval(dataRefreshTimer);
    dataRefreshTimer = null;
  }
}

async function refreshEvents() {
  try {
    const data = await getJSON(API.events);
    eventsData = data.events || [];
    if (eventsData.length > 0 && !hasEverHadData) {
      hasEverHadData = true;
      showSections();
    }
    renderEvents();
    updateStats();
  } catch (e) { /* silent */ }
}

async function refreshAnalyses() {
  try {
    const data = await getJSON(API.analyses);
    analysesData = data.analyses || [];
    if (analysesData.length > 0 && !hasEverHadData) {
      hasEverHadData = true;
      showSections();
    }
    updateStats();
  } catch (e) { /* silent */ }
}

function renderEvents() {
  const el = document.getElementById("events-list");
  if (!eventsData.length) {
    el.innerHTML = '<div class="empty-state">No Falco events yet. Run the pipeline or attacker first.</div>';
    return;
  }
  el.innerHTML = eventsData.map(e => {
    const time = e.time ? new Date(e.time).toLocaleTimeString() : "";
    return `<div class="event-item" onclick="analyzeEvent('${e.id}')">
      <div class="event-rule">${esc(e.rule)}</div>
      <div class="event-meta">
        <span class="priority-badge priority-${e.priority}">${e.priority}</span>
        <span>${time}</span>
        <span>${esc(e.output?.slice(0, 80))}...</span>
      </div>
    </div>`;
  }).join("");
}

async function analyzeEvent(eventId) {
  document.getElementById("analysis-list").innerHTML = '<div class="empty-state"><span class="loading"></span> Analyzing...</div>';
  try {
    const data = await getJSON(API.analyze, { method: "POST", body: JSON.stringify({ event_id: eventId }) });
    if (data.analysis) renderAnalysis(data.analysis, "analysis-list");
    await refreshAnalyses();
    updateStats();
  } catch (e) {
    document.getElementById("analysis-list").innerHTML = `<div class="empty-state">Analysis error: ${e.message}</div>`;
  }
}

async function analyzeAll() {
  document.getElementById("analysis-list").innerHTML = '<div class="empty-state"><span class="loading"></span> Analyzing all events in background...</div>';
  try {
    await getJSON(API.analyze, { method: "POST", body: JSON.stringify({ analyze_all: true }) });
    let pollAttempts = 0;
    const poll = setInterval(async () => {
      pollAttempts++;
      await refreshAnalyses();
      if (analysesData.length > 0 || pollAttempts > 60) {
        clearInterval(poll);
        renderAllAnalyses();
        updateStats();
      }
    }, 3000);
  } catch (e) {
    document.getElementById("analysis-list").innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

function renderAllAnalyses() {
  const el = document.getElementById("analysis-list");
  if (!analysesData.length) {
    el.innerHTML = '<div class="empty-state">No analyses yet.</div>';
    return;
  }
  el.innerHTML = analysesData.map(a => {
    const s = a._source;
    const score = s.risk_score || 0;
    const scoreClass = score >= 8 ? "critical" : score >= 5 ? "high" : score >= 3 ? "medium" : "low";
    return `<div class="event-item" onclick="showRemediation('${a._id}')">
      <div class="event-rule">${esc(s.attack_name || "Unknown")}</div>
      <div class="event-meta">
        <span class="flex-center"><span class="score-circle ${scoreClass}" style="width:24px;height:24px;font-size:10px">${score}</span> Risk: ${score}/10</span>
        <span>${(s.cve_mapping || []).join(", ") || "No CVE"}</span>
        <span>${(s.mitre_attack || []).join(", ") || "No MITRE"}</span>
      </div>
    </div>`;
  }).join("");
}

function renderAnalysis(analysis, targetId) {
  const el = document.getElementById(targetId);
  const score = analysis.risk_score || 0;
  const scoreClass = score >= 8 ? "critical" : score >= 5 ? "high" : score >= 3 ? "medium" : "low";
  const steps = analysis.remediation_steps || [];

  el.innerHTML = `<div class="analysis-panel">
    <div class="analysis-section">
      <label>Attack Name</label>
      <div style="font-size:16px;font-weight:600">${esc(analysis.attack_name || "Unknown")}</div>
    </div>
    <div class="analysis-section">
      <label>Description</label>
      <div style="font-size:13px;color:#8b949e">${esc(analysis.description || "No description")}</div>
    </div>
    <div class="analysis-section">
      <label>Risk Score</label>
      <div class="risk-score">
        <span class="score-circle ${scoreClass}">${score}</span>
        <span style="font-size:13px">${esc(analysis.risk_explanation || "")}</span>
      </div>
    </div>
    <div class="analysis-section">
      <label>CVE & MITRE ATT&CK</label>
      <div class="flex">
        ${(analysis.cve_mapping || []).map(c => `<span class="tag cve">${esc(c)}</span>`).join("")}
        ${(analysis.mitre_attack || []).map(m => `<span class="tag mitre">${esc(m)}</span>`).join("")}
        ${(!analysis.cve_mapping?.length && !analysis.mitre_attack?.length) ? '<span style="font-size:12px;color:#8b949e">None mapped</span>' : ""}
      </div>
    </div>
    <div class="analysis-section">
      <label>Affected Infrastructure</label>
      <div class="flex">
        ${(analysis.affected_infrastructure || []).map(i => `<span class="tag">${esc(i)}</span>`).join("")}
      </div>
    </div>
    <div class="analysis-section">
      <label>Remediation Steps (${steps.length})</label>
      ${steps.length ? steps.map((s, i) => `<div class="remediation-step">
        <h4>${i+1}. ${esc(s.title || "Step")}</h4>
        <code>${esc(s.command || "")}</code>
        <div style="font-size:12px;color:#8b949e;margin-bottom:6px">${esc(s.description || "")}</div>
        <button class="btn-execute" onclick="executeRemediation('${analysis._id || selectedAnalysisId}', ${i}, this)">Execute Step ${i+1}</button>
        <div class="remediation-result" id="rem-result-${i}" style="display:none"></div>
      </div>`).join("") : '<div style="font-size:12px;color:#8b949e">No remediation steps available</div>'}
    </div>
  </div>`;
}

function showRemediation(analysisId) {
  selectedAnalysisId = analysisId;
  const analysis = analysesData.find(a => a._id === analysisId)?._source;
  if (analysis) {
    renderAnalysis({ ...analysis, _id: analysisId }, "analysis-list");
    document.getElementById("remediation-card").style.display = "block";
  }
}

async function executeRemediation(analysisId, stepIndex, btn) {
  btn.disabled = true;
  btn.textContent = "Executing...";
  const resultDiv = document.getElementById(`rem-result-${stepIndex}`);
  resultDiv.style.display = "block";
  resultDiv.innerHTML = '<span class="loading"></span> Running...';

  try {
    const data = await getJSON(API.remediate, { method: "POST", body: JSON.stringify({ analysis_id: analysisId, step_index: stepIndex }) });
    const r = data.remediation?.result || {};
    resultDiv.innerHTML = r.executed
      ? `<div class="success">Executed successfully</div><pre style="font-size:11px;margin-top:4px">${esc(r.output || "")}</pre>`
      : `<div class="fail">Failed</div><pre style="font-size:11px;margin-top:4px">${esc(r.output || r.notes || "")}</pre>`;
    btn.className = r.executed ? "btn-execute executed" : "btn-execute failed";
    btn.textContent = r.executed ? "Executed" : "Failed";
    await refreshAnalyses();
    updateStats();
  } catch (e) {
    resultDiv.innerHTML = `<div class="fail">Error: ${esc(e.message)}</div>`;
    btn.className = "btn-execute failed";
    btn.textContent = "Error";
  }
  btn.disabled = false;
}

async function updateStats() {
  document.getElementById("stat-events").textContent = eventsData.length;
  document.getElementById("stat-analyzed").textContent = analysesData.length;
  const critical = analysesData.filter(a => (a._source?.risk_score || 0) >= 8).length;
  document.getElementById("stat-critical").textContent = critical;
  try {
    const remData = await getJSON(API.remediations);
    document.getElementById("stat-remediations").textContent = remData.remediations?.length || 0;
  } catch (e) { /* ignore */ }
}

function esc(s) { if (!s) return ""; const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

// ===== ORCHESTRATION =====

async function startPipeline() {
  const btn = document.getElementById("btn-pipeline");
  btn.disabled = true;
  btn.textContent = "Starting...";
  document.getElementById("orchestration-logs").innerHTML = "";

  try {
    const data = await getJSON(API.orchestrate, {
      method: "POST",
      body: JSON.stringify({ goal: "Set up the full container security lab: start all infrastructure, launch all attacks, detect them with Falco, analyze with AI, and report results." })
    });
    orchestrationSessionId = data.session_id;
    btn.textContent = "Pipeline Running...";
    addOrchestrationLog("system", "Pipeline started", "info");
    startOrchestrationPolling();
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Run Full Pipeline";
    addOrchestrationLog("system", `Error: ${e.message}`, "error");
  }
}

function startOrchestrationPolling() {
  if (orchestrationPollTimer) clearInterval(orchestrationPollTimer);
  orchestrationPollTimer = setInterval(pollOrchestration, 2000);
  pollOrchestration();
}

async function pollOrchestration() {
  if (!orchestrationSessionId) return;
  try {
    const data = await getJSON(`${API.orchestrate}/${orchestrationSessionId}`);
    updatePipelineUI(data);

    if (data.status === "complete" || data.status === "failed") {
      clearInterval(orchestrationPollTimer);
      orchestrationPollTimer = null;
      const btn = document.getElementById("btn-pipeline");
      btn.disabled = false;
      if (data.status === "complete") {
        btn.textContent = "Run Full Pipeline";
        addOrchestrationLog("system", "Pipeline completed successfully!", "success");
        hasEverHadData = true;
        showSections();
        startDataRefresh();
        await refreshEvents();
        await refreshAnalyses();
        renderAllAnalyses();
        updateStats();
      } else {
        btn.textContent = "Pipeline Failed";
        addOrchestrationLog("system", "Pipeline failed", "error");
      }
    }
  } catch (e) { /* ignore polling errors */ }
}

function updatePipelineUI(data) {
  const phases = ["setup", "attack", "monitor", "analyze", "remediate", "complete"];
  const currentTool = data.phase || "";

  let currentPhaseIdx = -1;
  if (currentTool.includes("setup") || currentTool.includes("infra")) currentPhaseIdx = 0;
  else if (currentTool.includes("attack")) currentPhaseIdx = 1;
  else if (currentTool.includes("wait") || currentTool.includes("monitor") || currentTool.includes("check")) currentPhaseIdx = 2;
  else if (currentTool.includes("analyze")) currentPhaseIdx = 3;
  else if (currentTool.includes("remedi") || currentTool.includes("remediate")) currentPhaseIdx = 4;
  else if (data.phase === "complete") currentPhaseIdx = 5;

  document.querySelectorAll(".pipeline-phase").forEach((el, i) => {
    const indicator = el.querySelector(".phase-indicator");
    if (i < currentPhaseIdx) {
      indicator.className = "phase-indicator completed";
    } else if (i === currentPhaseIdx) {
      indicator.className = "phase-indicator running";
    } else {
      indicator.className = "phase-indicator pending";
    }
  });

  const logsDiv = document.getElementById("orchestration-logs");
  if (data.logs && data.logs.length > 0) {
    const newLogs = data.logs.slice(-100);
    logsDiv.innerHTML = newLogs.map(l => {
      const time = new Date(l.timestamp).toLocaleTimeString();
      const cls = l.type === "error" ? "log-error" : l.type === "tool_end" ? "log-success" : l.type === "tool_start" ? "log-active" : "log-info";
      let msg = l.data || "";
      if (msg.length > 2000) msg = msg.slice(0, 2000) + "... [truncated]";
      return `<div class="log-entry ${cls}"><span class="log-time">${time}</span><span class="log-agent">[${esc(l.agent || l.type)}]</span><span class="log-msg">${esc(msg)}</span></div>`;
    }).join("");
    logsDiv.scrollTop = logsDiv.scrollHeight;
  }
}

function addOrchestrationLog(agent, msg, type) {
  const logsDiv = document.getElementById("orchestration-logs");
  if (!logsDiv) return;
  const time = new Date().toLocaleTimeString();
  const cls = type === "error" ? "log-error" : type === "success" ? "log-success" : "log-info";
  logsDiv.innerHTML += `<div class="log-entry ${cls}"><span class="log-time">${time}</span><span class="log-agent">[${esc(agent)}]</span><span class="log-msg">${esc(msg)}</span></div>`;
  logsDiv.scrollTop = logsDiv.scrollHeight;
}

async function refreshOrchestration() {
  if (!orchestrationSessionId) {
    try {
      const data = await getJSON(`${API.orchestrate}/sessions`);
      const sessions = data.sessions || [];
      if (sessions.length > 0) {
        orchestrationSessionId = sessions[0].id;
        const s = sessions[0];
        if (s.status === "complete" || s.status === "failed") {
          hasEverHadData = true;
          showSections();
        }
        startOrchestrationPolling();
      }
    } catch (e) { /* ignore */ }
  } else {
    await pollOrchestration();
  }
}

// ===== CLEAR SESSION =====

async function clearSession() {
  if (!confirm("Delete all events, analyses, and remediations? This cannot be undone.")) return;
  const btn = document.getElementById("btn-clear");
  btn.disabled = true;
  btn.textContent = "Clearing...";
  try {
    const data = await getJSON("/api/clear", { method: "DELETE" });
    orchestrationSessionId = null;
    eventsData = [];
    analysesData = [];
    selectedAnalysisId = null;
    hasEverHadData = false;
    stopDataRefresh();
    document.getElementById("events-list").innerHTML = '<div class="empty-state">No Falco events yet.</div>';
    document.getElementById("analysis-list").innerHTML = '<div class="empty-state">No analyses yet.</div>';
    document.getElementById("remediation-card").style.display = "none";
    document.getElementById("orchestration-logs").innerHTML = '<div class="empty-state">Session cleared. Click "Run Full Pipeline" to start.</div>';
    document.querySelectorAll(".phase-indicator").forEach(el => el.className = "phase-indicator pending");
    hideSections();
    updateStats();
    btn.textContent = "Cleared";
    setTimeout(() => { btn.textContent = "Clear Session"; btn.disabled = false; }, 2000);
  } catch (e) {
    btn.textContent = "Error";
    setTimeout(() => { btn.textContent = "Clear Session"; btn.disabled = false; }, 2000);
  }
}

// Init - only show pipeline card, nothing else
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("orchestration-logs").innerHTML = '<div class="empty-state">Click "Run Full Pipeline" to start AI-driven orchestration</div>';
  refreshOrchestration();
});