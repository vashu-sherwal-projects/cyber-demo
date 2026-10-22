const $ = (id) => document.getElementById(id);

function showView(name) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("show"));
  $("view-" + name).classList.add("show");
  document.querySelectorAll(".nav").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  const titles = {overview:"Security overview", integrity:"File integrity checker", password:"Password strength audit", logs:"Log analyzer"};
  $("page-title").textContent = titles[name] || "CyberDesk";
}
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));

async function requestJson(url, options={}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function resultBox(id, html) { $(id).innerHTML = html; $(id).classList.remove("hidden"); }
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function showError(id, error) { resultBox(id, `<h3>Could not complete check</h3><p>${escapeHtml(error.message || error)}</p>`); }

(async function loadSystem() {
  try {
    const d = await requestJson("/api/system");
    $("python-version").textContent = d.python;
    $("hostname").textContent = d.hostname;
    $("local-ip").textContent = "Local IP: " + d.local_ip;
    $("platform").textContent = d.platform;
    $("local-time").textContent = d.time;
  } catch (_) {
    $("python-version").textContent = "Unavailable";
  }
})();

$("hash-form").addEventListener("submit", async e => {
  e.preventDefault();
  const file = $("file-input").files[0];
  if (!file) return;
  const data = new FormData();
  data.append("file", file);
  try {
    const d = await requestJson("/api/hash", {method:"POST", body:data});
    resultBox("hash-result", `<h3>SHA-256 result</h3><p><strong>File:</strong> ${escapeHtml(d.filename)} · <strong>Size:</strong> ${d.size_bytes.toLocaleString()} bytes</p><div class="hash-value">${escapeHtml(d.sha256)}</div><p>${escapeHtml(d.note)}</p><button class="btn btn-quiet" id="copy-hash">Copy hash</button>`);
    $("copy-hash").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(d.sha256); $("copy-hash").textContent = "Copied ✓"; }
      catch (_) { $("copy-hash").textContent = "Copy unavailable"; }
    });
  } catch (err) { showError("hash-result", err); }
});

$("toggle-password").addEventListener("click", () => {
  const input = $("password-input");
  input.type = input.type === "password" ? "text" : "password";
  $("toggle-password").textContent = input.type === "password" ? "Show" : "Hide";
});
$("password-form").addEventListener("submit", async e => {
  e.preventDefault();
  const password = $("password-input").value;
  try {
    const d = await requestJson("/api/password", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({password})});
    const checks = Object.entries(d.checks).map(([key, ok]) => `<span class="pill">${ok ? "✓" : "○"} ${escapeHtml(key.replaceAll("_"," "))}</span>`).join("");
    resultBox("password-result", `<h3>Result: ${escapeHtml(d.label)} · ${d.score}/${d.out_of}</h3><div class="bar"><span style="width:${d.score/d.out_of*100}%"></span></div><p>${escapeHtml(d.advice)}</p><div>${checks}</div><p>Reminder: this is a basic heuristic, not a guarantee against guessing or data breaches.</p>`);
    $("password-input").value = "";
  } catch (err) { showError("password-result", err); }
});

$("logs-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const d = await requestJson("/api/logs", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({text:$("log-input").value})});
    let findings = d.findings.length ? d.findings.map(f => `<div class="finding"><span class="pill">Line ${f.line}</span><span class="pill">${escapeHtml(f.type)}</span><code>${escapeHtml(f.text)}</code></div>`).join("") : "<p>No configured phrases matched. This does not prove the log is clean.</p>";
    resultBox("logs-result", `<h3>Analysis summary</h3><p>Lines scanned: <strong>${d.total_lines}</strong> · Findings: <strong>${d.findings.length}</strong></p><p>Scanned at ${escapeHtml(d.scanned_at)}</p>${findings}`);
  } catch (err) { showError("logs-result", err); }
});
