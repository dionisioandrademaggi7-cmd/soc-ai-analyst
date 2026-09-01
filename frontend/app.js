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

setInterval(async () => {
  try {
    const data = await api("/api/auth-live");
    const ev = data.events || [];
    $("foreign").textContent = ev.length
      ? ev.map((e) => `${e.kind} ${e.ip}`).join("\n")
      : (data.hint || "sem eventos no auth.log");
  } catch (e) {
    $("foreign").textContent = String(e.message);
  }
}, 5000);

$("btnDry").onclick = () => contain(false);
$("btnLive").onclick = () => { if (confirm("Bloquear IP de verdade neste host?")) contain(true); };

/* Alerta autonomo: poll 2s, beep + flash em alerta NOVO */
let lastLiveSig = null;
let audioCtx = null;

document.addEventListener("click", () => {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === "suspended") audioCtx.resume();
  } catch (e) { /* browsers sem AudioContext */ }
}, { once: true });

function beepLive() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    if (!audioCtx) audioCtx = new Ctx();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    o.type = "square";
    o.frequency.value = 880;
    g.gain.value = 0.08;
    o.connect(g);
    g.connect(audioCtx.destination);
    o.start();
    setTimeout(() => {
      try { o.stop(); } catch (e) {}
    }, 180);
  } catch (e) { /* nunca falhar o dashboard */ }
}

function flashLive() {
  const card = $("liveAlertCard");
  const st = $("status");
  if (card) {
    card.classList.remove("hot");
    void card.offsetWidth;
    card.classList.add("hot");
    setTimeout(() => card.classList.remove("hot"), 2500);
  }
  if (st) {
    st.classList.add("flash");
    setTimeout(() => st.classList.remove("flash"), 2500);
  }
}

function liveSig(alerts) {
  if (!alerts.length) return "";
  const a = alerts[alerts.length - 1];
  return `${a.timestamp}|${a.kind}|${a.ip}|${alerts.length}`;
}

function renderLive(data) {
  const running = !!data.running;
  const src = data.source || "—";
  const hint = data.hint ? ` · ${data.hint}` : "";
  const limiar = data.fail_threshold && data.window_sec
    ? ` · ${data.fail_threshold} falhas / ${data.window_sec}s`
    : "";
  $("liveAlertState").textContent = (running ? "a vigiar" : "parado") + ` · fonte: ${src}${limiar}${hint}`;

  const alerts = data.alerts || [];
  const box = $("liveAlerts");
  if (!alerts.length) {
    box.innerHTML = "<div class='out'>sem alertas autónomos ainda — a vigiar falhas SSH e logons</div>";
  } else {
    const last = alerts.slice(-8).reverse();
    box.innerHTML = last.map((a) => {
      const k = (a.kind || "").toUpperCase();
      const sev = k === "LOGIN" ? "high" : "medium";
      const step = a.next_step || "Abra o SOC AI Analyst (Triagem / Investigar) para o relatório detalhado.";
      const extra = a.contain_result ? `<div class="out">contain: ${a.contain_result}</div>` : "";
      return `<div class="alert"><span class="sev ${sev}">${k}</span> ${a.ip || ""}`
        + `<div class="out">${step}</div>${extra}</div>`;
    }).join("");
  }

  const sig = liveSig(alerts);
  if (lastLiveSig === null) {
    lastLiveSig = sig;
    return;
  }
  if (sig && sig !== lastLiveSig) {
    const newest = alerts[alerts.length - 1];
    beepLive();
    flashLive();
    if (newest && newest.ip) $("ip").value = newest.ip;
    setStatus(`ALERTA ${newest.kind} ${newest.ip} — use Triagem para o relatório`);
  }
  lastLiveSig = sig;
}

async function pollLive() {
  try {
    const data = await api("/api/alerts/live");
    renderLive(data);
  } catch (e) {
    const el = $("liveAlertState");
    if (el) el.textContent = "erro a ler /api/alerts/live: " + e.message;
  }
}

pollLive();
setInterval(pollLive, 2000);
