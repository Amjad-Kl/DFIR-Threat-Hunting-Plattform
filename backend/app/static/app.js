/**
 * Threat Hunting Workbench - Frontend Controller
 * Communicates with FastAPI backend endpoints (/api/v1/...)
 */

const state = {
  currentCaseId: null,
  cases: [],
  currentView: "dashboard",
  eventLimit: 50,
  eventOffset: 0,
};

// --- Notifications ---
function notify(message, type = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.style.cssText = `
    background: ${type === "error" ? "#7f1d1d" : type === "success" ? "#064e3b" : "#1e293b"};
    border: 1px solid ${type === "error" ? "#ef4444" : type === "success" ? "#10b981" : "#38bdf8"};
    color: #f1f5f9; padding: 10px 16px; border-radius: 6px; font-size: 13px;
    margin-bottom: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); display: flex; align-items: center; gap: 8px;
    animation: fadeIn 0.2s ease-in;
  `;
  toast.innerHTML = `<span>${type === "error" ? "⚠️" : type === "success" ? "✅" : "ℹ️"}</span> ${message}`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// --- API Helpers ---
async function api(path, options = {}) {
  try {
    const res = await fetch(`/api/v1${path}`, options);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Request failed");
    }
    if (res.status === 204) return null;
    return await res.json();
  } catch (error) {
    notify(error.message, "error");
    throw error;
  }
}

// --- Navigation ---
function switchView(viewName) {
  state.currentView = viewName;
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.toggle("active", item.dataset.view === viewName);
  });
  document.querySelectorAll(".view-container").forEach(el => {
    el.classList.toggle("active", el.id === `view-${viewName}`);
  });

  if (state.currentCaseId) {
    if (viewName === "dashboard") loadDashboard();
    if (viewName === "evidence") loadArtifacts();
    if (viewName === "events") loadEvents();
    if (viewName === "timeline") loadTimeline();
    if (viewName === "hunting") loadFindings();
    if (viewName === "iocs") loadIOCs();
    if (viewName === "reports") loadReports();
  }
}

// --- Case Management ---
async function loadCases() {
  const cases = await api("/cases");
  state.cases = cases;
  const select = document.getElementById("case-select");
  select.innerHTML = "";

  if (cases.length === 0) {
    select.innerHTML = '<option value="">No cases available</option>';
    document.getElementById("header-case-name").textContent = "No Active Case";
    return;
  }

  cases.forEach(c => {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = `${c.name} (${c.classification})`;
    select.appendChild(opt);
  });

  // Keep selected or select first
  if (!state.currentCaseId || !cases.find(c => c.id === state.currentCaseId)) {
    state.currentCaseId = cases[0].id;
  }
  select.value = state.currentCaseId;
  updateHeaderCase();
  switchView(state.currentView);
}

function updateHeaderCase() {
  const activeCase = state.cases.find(c => c.id === state.currentCaseId);
  if (activeCase) {
    document.getElementById("header-case-name").textContent = activeCase.name;
    document.getElementById("header-classification").textContent = activeCase.classification.toUpperCase();
    document.getElementById("header-stat-events").textContent = activeCase.event_count || 0;
    document.getElementById("header-stat-findings").textContent = activeCase.finding_count || 0;
    document.getElementById("header-stat-artifacts").textContent = activeCase.artifact_count || 0;
  }
}

// --- Dashboard ---
async function loadDashboard() {
  if (!state.currentCaseId) return;
  const stats = await api(`/cases/${state.currentCaseId}/stats`);
  const activeCase = state.cases.find(c => c.id === state.currentCaseId);

  document.getElementById("dash-total-events").textContent = stats.total_events;
  document.getElementById("dash-timerange").textContent = stats.earliest_event 
    ? `${stats.earliest_event.slice(0, 16)} — ${stats.latest_event.slice(0, 16)}` 
    : "No events ingested";

  // Sources pill list
  const srcContainer = document.getElementById("dash-sources");
  srcContainer.innerHTML = "";
  for (const [src, count] of Object.entries(stats.events_by_source)) {
    const badge = document.createElement("span");
    badge.className = "badge badge-info";
    badge.style.marginRight = "6px";
    badge.textContent = `${src.toUpperCase()}: ${count}`;
    srcContainer.appendChild(badge);
  }

  // Severities
  const sevContainer = document.getElementById("dash-severities");
  sevContainer.innerHTML = "";
  for (const [sev, count] of Object.entries(stats.events_by_severity)) {
    const badge = document.createElement("span");
    badge.className = `badge badge-${sev}`;
    badge.style.marginRight = "6px";
    badge.textContent = `${sev.toUpperCase()}: ${count}`;
    sevContainer.appendChild(badge);
  }

  // Top Findings
  const findings = await api(`/cases/${state.currentCaseId}/findings`);
  const tbody = document.getElementById("dash-findings-body");
  tbody.innerHTML = "";
  findings.slice(0, 5).forEach(f => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
      <td><strong>${escapeHtml(f.title)}</strong></td>
      <td>${escapeHtml(f.rule_name || "-")}</td>
      <td>${f.created_at.slice(0, 19).replace("T", " ")}</td>
    `;
    tbody.appendChild(tr);
  });
  if (findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-dim);">No findings identified yet. Run analysis to scan.</td></tr>';
  }
}

// --- Artifacts & Ingestion ---
async function loadArtifacts() {
  if (!state.currentCaseId) return;
  const artifacts = await api(`/cases/${state.currentCaseId}/artifacts`);
  const tbody = document.getElementById("artifacts-table-body");
  tbody.innerHTML = "";

  artifacts.forEach(a => {
    const tr = document.createElement("tr");
    const mb = (a.file_size / (1024 * 1024)).toFixed(2);
    tr.innerHTML = `
      <td><strong>${escapeHtml(a.filename)}</strong></td>
      <td><span class="badge badge-info">${a.artifact_type}</span></td>
      <td>${mb} MB</td>
      <td><code style="font-size:11px; color:var(--primary);">${a.sha256.slice(0, 16)}...</code></td>
      <td><span class="badge badge-${a.parsing_status === 'done' ? 'low' : a.parsing_status === 'error' ? 'critical' : 'medium'}">${a.parsing_status}</span></td>
      <td>${a.event_count}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="triggerParse('${a.id}')" ${a.parsing_status === 'parsing' ? 'disabled' : ''}>⚡ Parse</button>
        <button class="btn btn-danger btn-sm" onclick="deleteArtifact('${a.id}')">🗑️</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (artifacts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No evidence artifacts uploaded yet.</td></tr>';
  }
}

async function triggerParse(artifactId) {
  notify("Parsing artifact...", "info");
  try {
    const res = await api(`/artifacts/${artifactId}/parse`, { method: "POST" });
    notify(`Parsed successfully! Extracted ${res.events_extracted} events.`, "success");
    loadArtifacts();
    loadCases();
  } catch (err) {}
}

async function deleteArtifact(artifactId) {
  if (!confirm("Are you sure you want to remove this artifact and its file?")) return;
  await api(`/artifacts/${artifactId}`, { method: "DELETE" });
  notify("Artifact deleted", "info");
  loadArtifacts();
  loadCases();
}

// Upload Handling
async function uploadArtifactFile(file) {
  if (!state.currentCaseId) {
    notify("Please create or select a case first", "error");
    return;
  }
  const formData = new FormData();
  formData.append("file", file);

  notify(`Uploading ${file.name}...`, "info");
  try {
    const res = await fetch(`/api/v1/cases/${state.currentCaseId}/artifacts`, {
      method: "POST",
      body: formData,
    });
    if (!res.ok) throw new Error("Upload failed");
    notify(`Uploaded ${file.name}! Starting parsing...`, "success");
    const data = await res.json();
    await triggerParse(data.id);
  } catch (err) {
    notify(err.message, "error");
  }
}

// --- Event Explorer ---
async function loadEvents() {
  if (!state.currentCaseId) return;

  const sourceFilter = document.getElementById("ev-source-filter").value;
  const sevFilter = document.getElementById("ev-sev-filter").value;
  const onlySus = document.getElementById("ev-only-sus").checked;

  let url = `/cases/${state.currentCaseId}/events?limit=${state.eventLimit}&offset=${state.eventOffset}`;
  if (sourceFilter) url += `&source_type=${sourceFilter}`;
  if (sevFilter) url += `&severity=${sevFilter}`;
  if (onlySus) url += `&is_suspicious=true`;

  const res = await api(url);
  document.getElementById("ev-total-count").textContent = `Showing ${res.events.length} of ${res.total} events`;

  const tbody = document.getElementById("events-table-body");
  tbody.innerHTML = "";

  res.events.forEach(e => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = () => showEventModal(e);

    const target = e.command_line || e.registry_key || e.file_path || e.dest_ip || "-";
    const shortTarget = target.length > 70 ? target.slice(0, 70) + "..." : target;

    tr.innerHTML = `
      <td style="font-size:12px; font-family:monospace;">${e.timestamp.replace("T", " ").slice(0, 19)}</td>
      <td><span class="badge badge-info">${e.source_type}</span></td>
      <td><strong>${escapeHtml(e.event_type)}</strong></td>
      <td><span class="badge badge-${e.severity}">${e.severity}</span></td>
      <td>${escapeHtml(e.process_name || "-")}</td>
      <td style="font-family:monospace; font-size:11px; color:var(--text-muted);">${escapeHtml(shortTarget)}</td>
      <td>
        ${e.is_suspicious ? '<span class="badge badge-high">⚠️ SUS</span>' : ''}
        ${e.is_ioc_match ? '<span class="badge badge-critical">🎯 IOC</span>' : ''}
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (res.events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No events match the current filter.</td></tr>';
  }
}

async function searchEventsFTS() {
  const query = document.getElementById("ev-search-input").value.trim();
  if (!query) {
    loadEvents();
    return;
  }
  const res = await api(`/cases/${state.currentCaseId}/events/search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: query, limit: 100 }),
  });

  document.getElementById("ev-total-count").textContent = `Found ${res.count} search matches`;
  const tbody = document.getElementById("events-table-body");
  tbody.innerHTML = "";

  res.results.forEach(e => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = () => showEventModal(e);
    tr.innerHTML = `
      <td style="font-size:12px; font-family:monospace;">${e.timestamp.replace("T", " ").slice(0, 19)}</td>
      <td><span class="badge badge-info">${e.source_type}</span></td>
      <td><strong>${escapeHtml(e.event_type || "-")}</strong></td>
      <td><span class="badge badge-${e.severity}">${e.severity}</span></td>
      <td>${escapeHtml(e.process_name || "-")}</td>
      <td style="font-family:monospace; font-size:11px;">${escapeHtml((e.command_line || e.registry_key || "").slice(0, 70))}</td>
      <td>${e.is_suspicious ? '<span class="badge badge-high">⚠️</span>' : ''}</td>
    `;
    tbody.appendChild(tr);
  });
}

function showEventModal(event) {
  document.getElementById("modal-event-title").textContent = `Event Detail: ${event.event_type || 'Event'}`;
  document.getElementById("modal-event-time").textContent = event.timestamp;
  document.getElementById("modal-event-source").textContent = `${event.source_type} (Event ID: ${event.event_id || 'N/A'})`;
  document.getElementById("modal-event-mitre").textContent = event.mitre_technique || "None";
  document.getElementById("modal-event-cmd").textContent = event.command_line || event.registry_key || event.file_path || "N/A";

  let rawDisplay = event.raw_data;
  try {
    rawDisplay = JSON.stringify(JSON.parse(event.raw_data), null, 2);
  } catch (e) {}
  document.getElementById("modal-event-raw").textContent = rawDisplay || "No raw payload stored.";

  document.getElementById("event-modal").classList.add("active");
}

// --- Forensic Timeline ---
async function loadTimeline() {
  if (!state.currentCaseId) return;
  const res = await api(`/cases/${state.currentCaseId}/timeline/full`);

  document.getElementById("tl-total-events").textContent = res.total_events;
  document.getElementById("tl-suspicious-count").textContent = res.summary.suspicious_count;
  document.getElementById("tl-clusters-count").textContent = res.clusters.length;
  document.getElementById("tl-gaps-count").textContent = res.gaps.length;

  // Render Clusters & Gaps
  const clusterBox = document.getElementById("tl-clusters-list");
  clusterBox.innerHTML = "";
  res.clusters.forEach(c => {
    const div = document.createElement("div");
    div.className = "card";
    div.style.marginBottom = "8px";
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between;">
        <strong>⚡ Burst: ${c.event_count} Events</strong>
        <span class="badge badge-high">${c.sources.join(", ")}</span>
      </div>
      <div class="card-subtext">${c.start.slice(0, 19).replace("T", " ")} — ${c.end.slice(0, 19).replace("T", " ")}</div>
    `;
    clusterBox.appendChild(div);
  });
  if (res.clusters.length === 0) {
    clusterBox.innerHTML = '<div style="color:var(--text-dim); font-size:12px;">No sudden event bursts detected.</div>';
  }

  const gapsBox = document.getElementById("tl-gaps-list");
  gapsBox.innerHTML = "";
  res.gaps.forEach(g => {
    const div = document.createElement("div");
    div.className = "card";
    div.style.marginBottom = "8px";
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between;">
        <strong>⏳ Inactivity Gap (${g.duration_human})</strong>
        <span class="badge badge-info">> 1 hour</span>
      </div>
      <div class="card-subtext">${g.start.slice(0, 19).replace("T", " ")} → ${g.end.slice(0, 19).replace("T", " ")}</div>
    `;
    gapsBox.appendChild(div);
  });
  if (res.gaps.length === 0) {
    gapsBox.innerHTML = '<div style="color:var(--text-dim); font-size:12px;">No major event gaps (> 1h) detected.</div>';
  }
}

// --- Threat Hunting & Detection ---
async function runAnalysis(endpoint = "/analyze") {
  if (!state.currentCaseId) return;
  notify("Running Threat Hunting Engines...", "info");
  const res = await api(`/cases/${state.currentCaseId}${endpoint}`, { method: "POST" });
  notify(`Analysis completed! Found ${res.total_new_findings ?? res.findings ?? 0} new detections.`, "success");
  loadFindings();
  loadCases();
}

async function loadFindings() {
  if (!state.currentCaseId) return;
  const findings = await api(`/cases/${state.currentCaseId}/findings?include_fp=true`);
  const tbody = document.getElementById("findings-table-body");
  tbody.innerHTML = "";

  findings.forEach(f => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
      <td>
        <strong>${escapeHtml(f.title)}</strong>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(f.description || "")}</div>
      </td>
      <td><span class="badge badge-info">${f.finding_type}</span></td>
      <td><code>${escapeHtml(f.rule_name || "-")}</code></td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="toggleFalsePositive('${f.id}')">
          ${f.false_positive ? '❌ False Positive' : '✅ Confirmed'}
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-dim);">No findings yet. Click "⚡ Run Full Hunt" above.</td></tr>';
  }
}

async function toggleFalsePositive(findingId) {
  await api(`/cases/${state.currentCaseId}/findings/${findingId}/toggle-fp`, { method: "PUT" });
  loadFindings();
}

// --- IOCs ---
async function loadIOCs() {
  const iocs = await api(`/iocs?case_id=${state.currentCaseId || ''}`);
  const tbody = document.getElementById("iocs-table-body");
  tbody.innerHTML = "";

  iocs.forEach(ioc => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-info">${ioc.ioc_type}</span></td>
      <td><code style="color:var(--primary);">${escapeHtml(ioc.ioc_value)}</code></td>
      <td>${escapeHtml(ioc.description || "-")}</td>
      <td><span class="badge badge-${ioc.confidence === 'high' ? 'critical' : 'medium'}">${ioc.confidence}</span></td>
      <td><button class="btn btn-danger btn-sm" onclick="deleteIOC('${ioc.id}')">🗑️</button></td>
    `;
    tbody.appendChild(tr);
  });

  if (iocs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-dim);">No IOCs configured. Add one or import CSV below.</td></tr>';
  }
}

async function createIOC(e) {
  e.preventDefault();
  const payload = {
    case_id: state.currentCaseId,
    ioc_type: document.getElementById("ioc-type-input").value,
    ioc_value: document.getElementById("ioc-val-input").value.trim(),
    description: document.getElementById("ioc-desc-input").value.trim(),
    confidence: document.getElementById("ioc-conf-input").value,
  };
  await api("/iocs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  notify("IOC created successfully", "success");
  document.getElementById("ioc-form").reset();
  loadIOCs();
}

async function deleteIOC(iocId) {
  await api(`/iocs/${iocId}`, { method: "DELETE" });
  notify("IOC deleted", "info");
  loadIOCs();
}

// --- Reports ---
async function loadReports() {
  if (!state.currentCaseId) return;
  const reports = await api(`/cases/${state.currentCaseId}/reports`);
  const tbody = document.getElementById("reports-table-body");
  tbody.innerHTML = "";

  reports.forEach(r => {
    const tr = document.createElement("tr");
    const kb = (r.size / 1024).toFixed(1);
    tr.innerHTML = `
      <td><strong>${escapeHtml(r.filename)}</strong></td>
      <td>${kb} KB</td>
      <td>
        <a class="btn btn-primary btn-sm" href="/api/v1/cases/${state.currentCaseId}/reports/${r.filename}" target="_blank">📄 View Report</a>
      </td>
    `;
    tbody.appendChild(tr);
  });

  if (reports.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: var(--text-dim);">No reports generated yet. Click Generate below.</td></tr>';
  }
}

async function generateReport(type = "full") {
  if (!state.currentCaseId) return;
  notify(`Generating ${type} report...`, "info");
  await api(`/cases/${state.currentCaseId}/reports/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report_type: type, analyst_name: "Threat Hunter" }),
  });
  notify("Report generated successfully!", "success");
  loadReports();
}

// --- Utilities ---
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- Modal Helper ---
function closeModal() {
  document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
}

// --- Init Event Handlers ---
window.addEventListener("DOMContentLoaded", () => {
  // Navigation clicks
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => switchView(item.dataset.view));
  });

  // Case switch
  document.getElementById("case-select").addEventListener("change", (e) => {
    state.currentCaseId = e.target.value;
    updateHeaderCase();
    switchView(state.currentView);
  });

  // File Dropzone
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");

  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length) uploadArtifactFile(e.target.files[0]);
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) uploadArtifactFile(e.dataTransfer.files[0]);
  });

  // IOC Form
  document.getElementById("ioc-form").addEventListener("submit", createIOC);

  // New Case Modal
  document.getElementById("btn-new-case").addEventListener("click", () => {
    document.getElementById("new-case-modal").classList.add("active");
  });

  document.getElementById("new-case-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      name: document.getElementById("case-name-input").value.trim(),
      description: document.getElementById("case-desc-input").value.trim(),
      analyst: document.getElementById("case-analyst-input").value.trim() || "Lead Hunter",
      classification: document.getElementById("case-class-input").value,
    };
    const newCase = await api("/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    notify(`Case "${newCase.name}" created!`, "success");
    closeModal();
    state.currentCaseId = newCase.id;
    await loadCases();
  });

  // Initial load
  loadCases();
});
