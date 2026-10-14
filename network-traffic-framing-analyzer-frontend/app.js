const API_BASE = "http://127.0.0.1:5000";

const $ = (id) => document.getElementById(id);
let frames = [];
let selectedId = null;
let captureTimer = null;
let captureRunning = false;
let currentView = "dashboard";

function showAlert(message, type = "info") {
  const el = $("alert");
  el.textContent = message;
  el.className = `alert ${type === "error" ? "error" : type === "success" ? "success" : ""}`;
  el.classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function hideAlert() { $("alert").classList.add("hidden"); }
async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) throw new Error(data.error || data.message || `Request failed (${response.status})`);
  return data;
}
function setBackend(online, message = "") {
  $("sideStatus").textContent = online ? "Backend connected" : "Backend offline";
  $("sideStatusDetail").textContent = online ? "127.0.0.1:5000" : "Start the Flask API";
  $("sideStatusDot").className = `status-dot ${online ? "good" : "bad"}`;
  $("statBackend").textContent = online ? "Connected" : "Offline";
  $("statBackendSub").textContent = message || (online ? "Flask API responding" : "Check backend terminal");
}
async function checkHealth() {
  try {
    const data = await api("/api/health");
    setBackend(true, data.message || "Flask API responding");
    return true;
  } catch (e) {
    setBackend(false);
    return false;
  }
}
function first(obj, keys, fallback = "—") {
  for (const key of keys) if (obj && obj[key] !== undefined && obj[key] !== null && obj[key] !== "") return obj[key];
  return fallback;
}
function getProtocol(f) {
  return String(first(f, ["protocol", "highest_layer", "transport_protocol", "network_protocol"], "UNKNOWN")).toUpperCase();
}
function getSource(f) { return first(f, ["source", "src", "src_ip", "source_ip", "src_mac", "source_mac"]); }
function getDestination(f) { return first(f, ["destination", "dst", "dst_ip", "destination_ip", "dst_mac", "destination_mac"]); }
function getLength(f) { return Number(first(f, ["length", "frame_length", "captured_length", "len"], 0)) || 0; }
function getInfo(f) { return first(f, ["info", "summary", "description"], `${getProtocol(f)} frame`); }
function getId(f, i) { return first(f, ["frame_number", "number", "id", "index"], i + 1); }
function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
function normalizeFrameList(data) {
  if (Array.isArray(data)) return data;
  for (const key of ["frames", "packets", "results", "data"]) if (Array.isArray(data?.[key])) return data[key];
  return [];
}
function updateStats() {
  $("statFrames").textContent = frames.length.toLocaleString();
  $("statProtocols").textContent = new Set(frames.map(getProtocol)).size.toLocaleString();
  $("statBytes").textContent = formatBytes(frames.reduce((sum, f) => sum + getLength(f), 0));
  $("frameCountBadge").textContent = `${frames.length} frame${frames.length === 1 ? "" : "s"}`;
  $("framesFooter").textContent = frames.length ? `Showing ${frames.length} analyzed frame${frames.length === 1 ? "" : "s"}` : "Waiting for frame data";
}
function renderFrames() {
  const body = $("framesBody");
  const query = $("frameSearch").value.trim().toLowerCase();
  const protocol = $("protocolFilter").value.toUpperCase();
  const filtered = frames.map((frame, i) => ({ frame, i })).filter(({ frame }) => {
    const searchable = `${getProtocol(frame)} ${getSource(frame)} ${getDestination(frame)} ${getInfo(frame)} ${JSON.stringify(frame)}`.toLowerCase();
    return (!query || searchable.includes(query)) && (!protocol || getProtocol(frame).includes(protocol));
  });
  if (!filtered.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty-state">${frames.length ? "No frames match your filters." : "No frames yet. Load demo data or analyze a capture file."}</td></tr>`;
    return;
  }
  body.innerHTML = filtered.map(({ frame, i }) => {
    const id = getId(frame, i);
    const p = getProtocol(frame);
    const tag = p.toLowerCase().replace(/[^a-z]/g, "");
    return `<tr data-index="${i}" class="${selectedId === i ? "selected" : ""}">
      <td>${escapeHtml(id)}</td><td><span class="protocol-tag ${tag}">${escapeHtml(p)}</span></td>
      <td>${escapeHtml(getSource(frame))}</td><td>${escapeHtml(getDestination(frame))}</td>
      <td>${getLength(frame)} B</td><td title="${escapeHtml(getInfo(frame))}">${escapeHtml(shorten(getInfo(frame), 36))}</td></tr>`;
  }).join("");
  body.querySelectorAll("tr[data-index]").forEach(row => row.addEventListener("click", () => selectFrame(Number(row.dataset.index))));
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function shorten(value, max) { const s = String(value ?? "—"); return s.length > max ? s.slice(0, max - 1) + "…" : s; }
function renderFieldRows(obj) {
  if (!obj || typeof obj !== "object") return "";
  return Object.entries(obj).map(([key, value]) => {
    if (value === null || value === undefined || typeof value === "object") return "";
    return `<div class="field-row"><span>${escapeHtml(key.replaceAll("_", " "))}</span><span>${escapeHtml(value)}</span></div>`;
  }).join("");
}
function selectFrame(index) {
  if (!frames[index]) return;
  selectedId = index;
  renderFrames();
  const f = frames[index];
  $("selectedFrameSubtitle").textContent = `Frame ${getId(f, index)} · ${getLength(f)} bytes`;
  const protocol = getProtocol(f);
  const layers = first(f, ["layers", "decoded_layers", "layer_details"], null);
  const fields = first(f, ["fields", "header_fields", "details"], null);
  const payload = first(f, ["payload_ascii", "payload_hex", "payload", "data_hex"], "");
  const payloadHex = first(f, ["payload_hex", "data_hex", "hex"], "");
  const payloadAscii = first(f, ["payload_ascii", "ascii"], "");
  let layerHtml = "";
  if (Array.isArray(layers)) {
    layerHtml = layers.map(layer => {
      if (typeof layer === "string") return `<div class="field-row"><span>Layer</span><span>${escapeHtml(layer)}</span></div>`;
      const title = first(layer, ["name", "layer", "protocol"], "Layer");
      return `<div class="section-label">${escapeHtml(title)}</div>${renderFieldRows(layer.fields || layer)}`;
    }).join("");
  } else if (layers && typeof layers === "object") {
    layerHtml = Object.entries(layers).map(([name, value]) => `<div class="section-label">${escapeHtml(name)}</div>${renderFieldRows(value)}`).join("");
  }
  if (!layerHtml && fields && typeof fields === "object") layerHtml = renderFieldRows(fields);
  const topLevel = renderFieldRows(Object.fromEntries(Object.entries(f).filter(([k,v]) => !["layers","decoded_layers","layer_details","fields","header_fields","details","payload","payload_hex","payload_ascii","data_hex","hex","raw_hex"].includes(k) && typeof v !== "object")));
  const hexDisplay = typeof payloadHex === "string" ? payloadHex : JSON.stringify(payloadHex);
  const asciiDisplay = typeof payloadAscii === "string" ? payloadAscii : "";
  $("inspectorContent").innerHTML = `
    <div class="frame-summary"><div class="summary-title">Frame ${escapeHtml(getId(f, index))} <span class="protocol-tag ${protocol.toLowerCase()}">${escapeHtml(protocol)}</span></div><div class="summary-sub">${escapeHtml(getSource(f))} → ${escapeHtml(getDestination(f))}</div><div class="summary-sub">${escapeHtml(getInfo(f))}</div></div>
    <div class="section-label">DECODED LAYERS & FIELDS</div>
    ${layerHtml || `<div class="field-row"><span>Protocol</span><span>${escapeHtml(protocol)}</span></div>`}
    ${topLevel ? `<div class="section-label">FRAME METADATA</div>${topLevel}` : ""}
    <div class="section-label">PAYLOAD · HEX</div><div class="payload-block">${escapeHtml(hexDisplay || (typeof payload === "string" ? payload : "Payload unavailable in response."))}</div>
    ${asciiDisplay ? `<div class="section-label">PAYLOAD · ASCII</div><div class="payload-block">${escapeHtml(asciiDisplay)}</div>` : ""}
    <div class="section-label">FRAME LENGTH</div><div class="field-row"><span>Captured length</span><span>${getLength(f)} bytes</span></div>
    <div class="field-row"><span>FCS / trailer</span><span>${escapeHtml(first(f, ["fcs_status", "trailer_status", "fcs"], "Not available in capture"))}</span></div>`;
}
function setFrames(data, message) {
  frames = normalizeFrameList(data);
  selectedId = null;
  updateStats();
  renderFrames();
  $("selectedFrameSubtitle").textContent = "Select a frame to view decoded fields.";
  $("inspectorContent").innerHTML = `<div class="inspector-empty"><div class="empty-graphic">⌘</div><strong>${frames.length ? "Select a frame" : "No frame selected"}</strong><span>${frames.length ? "Choose a row from the frame explorer." : "Pick demo data, upload a capture, or decode raw hex."}</span></div>`;
  if (message) showAlert(message, "success");
}
async function loadDemo() {
  hideAlert();
  try {
    const data = await api("/api/demo");
    setFrames(data, "Demo frames loaded successfully.");
  } catch (e) { showAlert(`Could not load demo data: ${e.message}`, "error"); }
}
async function analyzeHex(event) {
  event.preventDefault(); hideAlert();
  const hex = $("hexInput").value.trim();
  if (!hex) return showAlert("Paste a hexadecimal frame before decoding.", "error");
  const btn = $("analyzeHexBtn"); btn.disabled = true; btn.textContent = "Decoding…";
  try {
    const data = await api("/api/analyze/hex", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hex }) });
    const result = data.frame || data.result || data;
    setFrames([result], "Hex frame decoded successfully.");
    selectFrame(0);
  } catch (e) { showAlert(`Hex analysis failed: ${e.message}`, "error"); }
  finally { btn.disabled = false; btn.textContent = "Decode hex"; }
}
async function analyzePcap(event) {
  event.preventDefault(); hideAlert();
  const file = $("pcapInput").files[0];
  if (!file) return showAlert("Choose a PCAP or PCAPNG file first.", "error");
  const btn = $("analyzeFileBtn"); btn.disabled = true; btn.textContent = "Analyzing…";
  const form = new FormData(); form.append("file", file);
  try {
    const data = await api("/api/analyze/pcap", { method: "POST", body: form });
    setFrames(data, `Analyzed ${file.name} successfully.`);
    if (frames.length) selectFrame(0);
  } catch (e) { showAlert(`Capture analysis failed: ${e.message}`, "error"); }
  finally { btn.disabled = false; btn.textContent = "Analyze capture"; }
}
async function loadInterfaces() {
  hideAlert();
  try {
    const data = await api("/api/interfaces");
    const items = Array.isArray(data) ? data : (data.interfaces || data.data || []);
    $("interfaceSelect").innerHTML = items.length ? items.map(item => {
      const name = typeof item === "string" ? item : first(item, ["name", "interface", "id"], "");
      const label = typeof item === "string" ? item : first(item, ["description", "label"], name);
      return `<option value="${escapeHtml(name)}">${escapeHtml(label)}</option>`;
    }).join("") : `<option value="">No interfaces returned</option>`;
    if (!items.length) showAlert("The backend returned no interfaces. Check capture permissions and backend logs.");
  } catch (e) { showAlert(`Could not load interfaces: ${e.message}`, "error"); }
}
async function startCapture() {
  hideAlert();
  const iface = $("interfaceSelect").value;
  const count = Math.max(1, Math.min(1000, Number($("captureCount").value) || 50));
  if (!iface) return showAlert("Select a network interface first.", "error");
  try {
    await api("/api/capture/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interface: iface, count }) });
    captureRunning = true;
    $("startCaptureBtn").disabled = true; $("stopCaptureBtn").disabled = false;
    $("captureDot").className = "status-dot good"; $("captureStatus").textContent = `Capturing on ${iface}`;
    $("captureMeta").textContent = `Limit: ${count} frames`;
    captureTimer = window.setInterval(refreshCaptureFrames, 1600);
    showAlert("Live capture started. Incoming frames will appear in the explorer.", "success");
  } catch (e) { showAlert(`Could not start capture: ${e.message}`, "error"); }
}
async function refreshCaptureFrames() {
  try {
    const data = await api("/api/capture/frames");
    const incoming = normalizeFrameList(data);
    if (incoming.length) {
      frames = incoming; updateStats(); renderFrames();
      $("captureMeta").textContent = `${frames.length} frame${frames.length === 1 ? "" : "s"} collected`;
    }
    const status = await api("/api/capture/status");
    if (status.running === false && captureRunning) finishCapture("Capture completed");
  } catch (e) {
    if (captureRunning) showAlert(`Capture refresh failed: ${e.message}`, "error");
  }
}
async function stopCapture() {
  try { await api("/api/capture/stop", { method: "POST" }); finishCapture("Capture stopped"); }
  catch (e) { showAlert(`Could not stop capture: ${e.message}`, "error"); }
}
function finishCapture(message) {
  captureRunning = false;
  if (captureTimer) window.clearInterval(captureTimer);
  captureTimer = null;
  $("startCaptureBtn").disabled = false; $("stopCaptureBtn").disabled = true;
  $("captureDot").className = "status-dot"; $("captureStatus").textContent = message;
  $("captureMeta").textContent = `${frames.length} frames collected`;
}
function clearWorkspace() {
  frames = []; selectedId = null; updateStats(); renderFrames();
  $("inspectorContent").innerHTML = `<div class="inspector-empty"><div class="empty-graphic">⌘</div><strong>No frame selected</strong><span>Workspace cleared. Load a capture or demo data to begin.</span></div>`;
  $("selectedFrameSubtitle").textContent = "Select a frame to view decoded fields.";
}
function navigate(view) {
  currentView = view;
  const labels = { dashboard: ["Overview", "Network traffic, decoded.", "Inspect frame structure from capture files, live interfaces, or raw hexadecimal data."], capture: ["Live capture", "Observe traffic in real time.", "Choose an available interface and inspect authorized network traffic."], file: ["PCAP analysis", "Decode a capture file.", "Upload a PCAP or PCAPNG file to inspect headers, payloads, and protocols."], hex: ["Hex inspector", "Decode raw frame bytes.", "Paste hexadecimal bytes to inspect the frame structure."] };
  const info = labels[view] || labels.dashboard;
  $("breadcrumbPage").textContent = info[0]; $("pageTitle").textContent = info[1]; $("pageSubtitle").textContent = info[2];
  document.querySelectorAll(".nav-item").forEach(btn => btn.classList.toggle("active", btn.dataset.view === view));
  if (view === "capture") $("captureTool").scrollIntoView({ behavior: "smooth", block: "center" });
  if (view === "file") $("fileTool").scrollIntoView({ behavior: "smooth", block: "center" });
  if (view === "hex") $("hexTool").scrollIntoView({ behavior: "smooth", block: "center" });
}
$("refreshBtn").addEventListener("click", checkHealth);
$("demoBtn").addEventListener("click", loadDemo);
$("quickUploadBtn").addEventListener("click", () => { navigate("file"); $("pcapInput").click(); });
$("chooseFileBtn").addEventListener("click", () => $("pcapInput").click());
$("pcapInput").addEventListener("change", () => {
  const file = $("pcapInput").files[0];
  $("fileName").textContent = file ? `${file.name} · ${formatBytes(file.size)}` : "PCAP / PCAPNG · Backend upload limit applies";
  $("analyzeFileBtn").disabled = !file;
});
$("pcapForm").addEventListener("submit", analyzePcap);
$("hexForm").addEventListener("submit", analyzeHex);
$("frameSearch").addEventListener("input", renderFrames);
$("protocolFilter").addEventListener("change", renderFrames);
$("clearBtn").addEventListener("click", clearWorkspace);
$("loadInterfacesBtn").addEventListener("click", loadInterfaces);
$("startCaptureBtn").addEventListener("click", startCapture);
$("stopCaptureBtn").addEventListener("click", stopCapture);
document.querySelectorAll(".nav-item").forEach(btn => btn.addEventListener("click", () => navigate(btn.dataset.view)));
const dropZone = document.querySelector(".upload-zone");
["dragenter", "dragover"].forEach(name => dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.style.borderColor = "#6758e8"; dropZone.style.background = "#f6f5ff"; }));
["dragleave", "drop"].forEach(name => dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.style.borderColor = ""; dropZone.style.background = ""; }));
dropZone.addEventListener("drop", e => {
  const file = e.dataTransfer.files[0];
  if (file) {
    const transfer = new DataTransfer(); transfer.items.add(file); $("pcapInput").files = transfer.files;
    $("pcapInput").dispatchEvent(new Event("change"));
  }
});
checkHealth();
loadInterfaces();
