const $ = (id) => document.getElementById(id);

const map = L.map("map", { zoomControl: true, attributionControl: false }).setView([20, 0], 2);
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 18,
}).addTo(map);
const layer = L.layerGroup().addTo(map);

function setStatus(t) { $("status").textContent = t; }

async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function renderDiag(results) {
  if (!results.length) { $("diag").textContent = "Nenhum alerta."; return; }
  const rank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const worst = [...results].sort((a, b) => (rank[(a.severity || "").toLowerCase()] ?? 9) - (rank[(b.severity || "").toLowerCase()] ?? 9))[0];
  const sev = (worst.severity || "low").toLowerCase();
  $("diag").innerHTML = `<div><span class="sev ${sev}">${(worst.severity || "").toUpperCase()}</span> <strong>${worst.category || ""}</strong></div><p>${worst.summary || ""}</p>`;
}

function renderAlerts(results) {
  $("alerts").innerHTML = results.map((r) => {
    const sev = (r.severity || "low").toLowerCase();
    return `<div class="alert"><span class="sev ${sev}">${(r.severity || "").toUpperCase()}</span> ${r.category || ""}<div class="out">${r.summary || ""}</div></div>`;
  }).join("") || "<div class='out'>vazio</div>";
}

function renderMap(markers) {
  layer.clearLayers();
  const pts = [];
  (markers || []).forEach((m) => {
    if (m.lat == null || m.lon == null) return;
    const c = m.kind === "public" ? "#ff6b4a" : "#3ee0b0";
    const mk = L.circleMarker([m.lat, m.lon], { radius: 6, color: c, fillOpacity: 0.9 });
    mk.bindPopup(`${m.ip}<br>${m.label || ""}`);
    mk.addTo(layer);
    pts.push([m.lat, m.lon]);
  });
  if (pts.length) map.fitBounds(pts, { maxZoom: 4, padding: [30, 30] });
}

$("btnTriage").onclick = async () => {
  setStatus("triando...");
  try {
    const data = await api("/api/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: $("source").value, count: Number($("count").value || 5) }),
    });
    $("pillFonte").textContent = data.fonte;
    $("pillCount").textContent = data.count + " alertas";
    renderDiag(data.results || []);
    renderAlerts(data.results || []);
    renderMap(data.markers || []);
    if ((data.ips || [])[0]) $("ip").value = data.ips[0];
    setStatus("triagem ok");
  } catch (e) { setStatus("erro: " + e.message); }
};

$("btnSessions").onclick = async () => {
  try {
    const data = await api("/api/sessions");
    const f = data.foreign || [];
    $("foreign").textContent = f.length ? f.map((s) => `${s.user} ${s.ip} (${s.tty})`).join("\n") : "nenhuma sessao estrangeira";
    if (f[0]) $("ip").value = f[0].ip;
    setStatus("sessoes lidas");
  } catch (e) { setStatus("erro: " + e.message); }
};

$("btnDefense").onclick = async () => {
  try {
    const data = await api("/api/defense");
    $("containOut").textContent = (data.ufw?.message || "") + "\n\n" + (data.fail2ban?.message || "");
    setStatus("snapshot de defesa");
  } catch (e) { setStatus("erro: " + e.message); }
};

async function contain(execute) {
  const ip = $("ip").value.trim();
  if (!ip) return setStatus("informe um IP");
  try {
    const data = await api("/api/contain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, action: "block", execute }),
    });
    $("containOut").textContent = (data.dry_run ? "[DRY] " : "[LIVE] ") + data.message;
    setStatus(data.message);
  } catch (e) { setStatus("erro: " + e.message); }
}

setInterval(() => {
  $("btnSessions") && $("btnSessions").click();
}, 10000);

$("btnDry").onclick = () => contain(false);
$("btnLive").onclick = () => { if (confirm("Bloquear IP de verdade neste host?")) contain(true); };