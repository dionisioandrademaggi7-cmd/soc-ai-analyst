
const $ = (id) => document.getElementById(id);

function setStatus(t) {
  const el = $("status");
  if (el) el.textContent = t;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  let data = {};
  try {
    data = await res.json();
  } catch (_) {}
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : res.statusText);
  }
  return data;
}

function colorize(text) {
  let t = String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  t = t.replace(/\b(critical|cr[ií]tico|cr[ií]tica)\b/gi, '<span class="c-crit">$1</span>');
  t = t.replace(/\b(high|alta|alto)\b/gi, '<span class="c-high">$1</span>');
  t = t.replace(/\b(medium|m[eé]dia|medio)\b/gi, '<span class="c-med">$1</span>');
  t = t.replace(/\b(low|baixa|baixo|informational|info)\b/gi, '<span class="c-low">$1</span>');
  t = t.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, '<span class="c-ip">$1</span>');
  t = t.replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<span class="c-mitre">$1</span>');
  t = t.replace(
    /\b(malware|ransomware|brut[e]?\s*force|phishing|exfiltrat\w*|powershell|c2|command and control|login|failed|accepted)\b/gi,
    '<span class="c-crit">$1</span>'
  );
  t = t.replace(/\b(false positive|benign|informational)\b/gi, '<span class="c-low">$1</span>');
  return t;
}

const map = L.map("map", {
  zoomControl: true,
  attributionControl: false,
}).setView([20, 0], 2);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 18,
}).addTo(map);

const layer = L.layerGroup().addTo(map);
setTimeout(() => map.invalidateSize(), 300);

function renderMap(markers) {
  layer.clearLayers();
  const pts = [];
  (markers || []).forEach((m) => {
    if (m.lat == null || m.lon == null) return;
    L.circleMarker([m.lat, m.lon], {
      radius: 7,
      color: "#ffffff",
      fillColor: "#ff3355",
      fillOpacity: 0.95,
      weight: 2,
    })
      .bindPopup(`<b>${m.ip || ""}</b><br>${m.label || ""}`)
      .addTo(layer);
    pts.push([m.lat, m.lon]);
  });
  if (pts.length === 1) map.setView(pts[0], 5);
  else if (pts.length > 1) map.fitBounds(pts, { padding: [28, 28], maxZoom: 5 });
}

function renderDiag(results) {
  if (!results || !results.length) {
    $("diag").textContent = "Nenhum alerta.";
    return;
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const w = [...results].sort(
    (a, b) =>
      (rank[(a.severity || "").toLowerCase()] ?? 9) -
      (rank[(b.severity || "").toLowerCase()] ?? 9)
  )[0];
  const head = `${(w.severity || "").toUpperCase()} — ${w.category || ""}`;
  $("diag").innerHTML = colorize(head) + "<br><br>" + colorize(w.summary || "");
}

function renderAlerts(results) {
  $("alerts").innerHTML =
    (results || [])
      .map((r) => {
        const line = `${(r.severity || "").toUpperCase()} | ${r.category || ""}\n${r.summary || ""}`;
        return `<div class="alert-block">${colorize(line)}</div>`;
      })
      .join("") || "vazio";
}

async function contain(execute) {
  const ip = ($("ip").value || "").trim();
  if (!ip) {
    setStatus("sem IP no campo");
    return;
  }
  try {
    const data = await api("/api/contain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, action: "block", execute }),
    });
    $("containOut").textContent =
      (data.dry_run ? "[DRY] " : "[LIVE] ") + (data.message || "");
    setStatus(data.message || "contain ok");
  } catch (e) {
    setStatus("erro: " + e.message);
  }
}

$("btnTriage").onclick = async () => {
  setStatus("triando...");
  try {
    const data = await api("/api/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: $("source").value,
        count: Number($("count").value || 3),
      }),
    });
    $("pillFonte").textContent = data.fonte || "—";
    $("pillCount").textContent = (data.count || 0) + " ALERTAS";
    renderDiag(data.results || []);
    renderAlerts(data.results || []);
    renderMap(data.markers || []);
    if ((data.ips || [])[0]) $("ip").value = data.ips[0];
    setStatus("triagem ok");
    setTimeout(() => map.invalidateSize(), 100);
  } catch (e) {
    setStatus("erro: " + e.message);
  }
};

$("btnSessions").onclick = async () => {
  try {
    const data = await api("/api/sessions");
    const f = data.foreign || [];
    $("foreign").textContent = f.length
      ? f.map((s) => `${s.user} ${s.ip}`).join("\n")
      : "nenhuma sessao estrangeira";
    if (f[0] && f[0].ip) $("ip").value = f[0].ip;
    setStatus("sessoes lidas");
  } catch (e) {
    setStatus("erro: " + e.message);
  }
};

$("btnDefense").onclick = async () => {
  try {
    const data = await api("/api/defense");
    $("containOut").textContent =
      (data.ufw && data.ufw.message ? data.ufw.message : "") +
      "\n" +
      (data.fail2ban && data.fail2ban.message ? data.fail2ban.message : "");
    setStatus("defesa host");
  } catch (e) {
    setStatus("erro: " + e.message);
  }
};

$("btnDry").onclick = () => contain(false);
$("btnLive").onclick = () => {
  if (confirm("Bloquear IP de verdade neste host?")) contain(true);
};
$("btnBlockLast").onclick = () => {
  if (!$("ip").value.trim()) {
    setStatus("sem IP ainda");
    return;
  }
  if (confirm("Bloquear " + $("ip").value + "?")) contain(true);
};

/* Alerta autonomo: poll 2s, beep + flash em alerta NOVO */
let lastLiveSig = null;
let audioCtx = null;

document.addEventListener(
  "click",
  () => {
    try {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      if (audioCtx.state === "suspended") audioCtx.resume();
    } catch (e) {}
  },
  { once: true }
);

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
      try {
        o.stop();
      } catch (e) {}
    }, 180);
  } catch (e) {}
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
  const limiar =
    data.fail_threshold && data.window_sec
      ? ` · ${data.fail_threshold} falhas / ${data.window_sec}s`
      : "";

  const stateEl = $("liveAlertState");
  if (stateEl) {
    stateEl.textContent =
      (running ? "a vigiar" : "parado") + ` · fonte: ${src}${limiar}${hint}`;
  }

  const alerts = data.alerts || [];
  const box = $("liveAlerts") || $("foreign");
  if (!box) return;

  if (!alerts.length) {
    box.innerHTML =
      "<div class='out'>sem alertas ainda — cada FAIL/LOGIN novo aparece aqui</div>";
  } else {
    const last = alerts.slice(-8).reverse();
    box.innerHTML = last
      .map((a) => {
        const k = (a.kind || "").toUpperCase();
        const step =
          a.next_step ||
          "Abra Triagem / Investigar para o relatório detalhado.";
        const extra = a.contain_result
          ? `<div class="out">contain: ${a.contain_result}</div>`
          : "";
        return (
          `<div class="alert-block">${colorize(k + " " + (a.ip || ""))}` +
          `<div class="out">${colorize(step)}</div>${extra}</div>`
        );
      })
      .join("");
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
    setStatus(`ALERTA ${newest.kind} ${newest.ip} — use Triagem`);
  }
  lastLiveSig = sig;
}

async function pollLive() {
  try {
    const data = await api("/api/alerts/live");
    renderLive(data);
  } catch (e) {
    const el = $("liveAlertState");
    if (el) el.textContent = "erro /api/alerts/live: " + e.message;
  }
}

pollLive();
setInterval(pollLive, 2000);