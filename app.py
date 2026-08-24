import streamlit as st
import pandas as pd
import pydeck as pdk
import requests
import re
import time
from config import settings
from mock_splunk_client import MockSplunkClient
from local_log_client import LocalLogClient
from ai_analyst import AIAnalyst
import report_generator as rg

st.set_page_config(page_title="SOC AI Analyst", layout="wide", initial_sidebar_state="collapsed")

# ===================== CSS =====================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Rajdhani:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background: #020617;
    color: #e0f2fe;
}
.stApp {
    background:
        radial-gradient(ellipse 90% 50% at 50% -15%, rgba(6,182,212,0.12), transparent),
        radial-gradient(ellipse 50% 40% at 100% 0%, rgba(168,85,247,0.08), transparent),
        radial-gradient(ellipse 40% 30% at 0% 100%, rgba(239,68,68,0.07), transparent),
        #020617;
}
div[data-testid="stSidebar"] {
    background: rgba(2, 6, 23, 0.95);
    border-right: 1px solid rgba(34,211,238,0.12);
}

.hud-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 0.22em;
    color: #22d3ee;
    text-shadow: 0 0 24px rgba(34,211,238,0.55);
}
.hud-sub {
    font-size: 0.78rem;
    color: #64748b;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    margin-bottom: 1.2rem;
}

.map-frame {
    background: linear-gradient(160deg, rgba(8,20,40,0.85), rgba(2,8,20,0.95));
    border: 1px solid rgba(34,211,238,0.22);
    border-radius: 32px;
    padding: 14px;
    box-shadow: 0 0 50px rgba(34,211,238,0.07), inset 0 0 80px rgba(0,0,0,0.45);
    position: relative;
}
.map-frame::before {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: 32px;
    padding: 1px;
    background: linear-gradient(135deg, rgba(34,211,238,0.35), transparent 40%, rgba(168,85,247,0.2));
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events: none;
}

.diag {
    background: linear-gradient(145deg, rgba(15,23,42,0.95), rgba(2,8,20,0.98));
    border-radius: 22px;
    padding: 1.3rem 1.5rem;
    margin: 0.8rem 0 1rem 0;
}
.diag-critical { border-left: 3px solid #ef4444; box-shadow: 0 0 40px rgba(239,68,68,0.18); }
.diag-high     { border-left: 3px solid #f97316; box-shadow: 0 0 30px rgba(249,115,22,0.14); }
.diag-medium   { border-left: 3px solid #eab308; }
.diag-low      { border-left: 3px solid #22c55e; }
.diag-info     { border-left: 3px solid #22d3ee; }

.diag-label {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.62rem;
    letter-spacing: 0.22em;
    color: #64748b;
    margin-bottom: 0.4rem;
}
.diag-text { font-size: 1.12rem; font-weight: 600; color: #f0f9ff; line-height: 1.4; }
.diag-meta { font-size: 0.85rem; color: #94a3b8; margin-top: 0.5rem; }

.alert-card {
    background: rgba(15,23,42,0.75);
    border: 1px solid rgba(34,211,238,0.1);
    border-radius: 16px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.75rem;
}
.alert-card.critical { border-color: rgba(239,68,68,0.4); }
.alert-card.high     { border-color: rgba(249,115,22,0.35); }
.alert-card.medium   { border-color: rgba(234,179,8,0.3); }
.alert-card.low      { border-color: rgba(34,197,94,0.3); }

.sev-pill {
    display: inline-block;
    font-family: 'Orbitron', sans-serif;
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    padding: 0.2rem 0.65rem;
    border-radius: 999px;
    margin-right: 0.5rem;
}
.pill-critical { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
.pill-high     { background: rgba(249,115,22,0.2); color: #fdba74; border: 1px solid rgba(249,115,22,0.4); }
.pill-medium   { background: rgba(234,179,8,0.15); color: #fde047; border: 1px solid rgba(234,179,8,0.35); }
.pill-low      { background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.35); }
.pill-info     { background: rgba(34,211,238,0.15); color: #67e8f9; border: 1px solid rgba(34,211,238,0.35); }

.stButton > button {
    background: linear-gradient(135deg, #0e7490, #0891b2) !important;
    color: #ecfeff !important;
    border: 1px solid rgba(34,211,238,0.35) !important;
    border-radius: 999px !important;
    padding: 0.5rem 1.7rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.06em !important;
    box-shadow: 0 0 22px rgba(8,145,178,0.35) !important;
}
.stButton > button:hover {
    box-shadow: 0 0 32px rgba(34,211,238,0.55) !important;
    transform: translateY(-2px) !important;
}

div[data-testid="stMetric"] {
    background: rgba(15,23,42,0.7);
    border: 1px solid rgba(34,211,238,0.12);
    border-radius: 16px;
    padding: 0.7rem 1rem;
}
h1,h2,h3,h4 { color: #e0f2fe !important; font-family: 'Rajdhani', sans-serif !important; }
hr { border-color: rgba(34,211,238,0.1); }
</style>
""", unsafe_allow_html=True)

# IPs de documentação → coordenadas fixas (mock funciona no mapa)
DEMO_GEO = {
    "203.0.113.5":  {"lat": 39.9,  "lon": 116.4, "city": "Beijing"},
    "203.0.113.10": {"lat": 55.75, "lon": 37.62, "city": "Moscow"},
    "198.51.100.22":{"lat": 37.77, "lon": -122.42,"city": "San Francisco"},
    "198.51.100.8": {"lat": 51.5,  "lon": -0.12, "city": "London"},
    "192.0.2.15":   {"lat": 35.68, "lon": 139.69,"city": "Tokyo"},
    "203.0.113.50": {"lat": -23.55,"lon": -46.63,"city": "Sao Paulo"},
}

@st.cache_data(ttl=3600)
def geo_lookup(ip: str):
    if not ip:
        return None
    if ip in DEMO_GEO:
        d = DEMO_GEO[ip]
        return {"lat": d["lat"], "lon": d["lon"], "city": d["city"], "country": d["city"], "query": ip}
    if ip.startswith(("127.", "10.", "192.168.", "172.")):
        return None
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,query",
            timeout=4,
        )
        data = r.json()
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return None

@st.cache_data(ttl=600)
def my_location():
    try:
        ip = requests.get("https://api.ipify.org", timeout=4).text.strip()
        g = geo_lookup(ip)
        if g:
            return {**g, "ip": ip}
    except Exception:
        pass
    return None

def pull_ips(results):
    found = []
    for r in results:
        blob = str(r.raw_alert) + " " + " ".join(str(x) for x in (r.indicators or []))
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
            found.append(m)
    return list(dict.fromkeys(found))

# ===================== HEADER =====================
st.markdown('<div class="hud-title">SOC AI ANALYST</div>', unsafe_allow_html=True)
st.markdown('<div class="hud-sub">Threat Intelligence  ·  Live Triage  ·  Containment</div>', unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### Fonte")
    fonte = st.radio("fonte", ["Mock", "Logs locais", "Splunk"], index=0, label_visibility="collapsed")
    count = st.slider("Alertas", 1, 20, 5)
    st.caption("Captura de rede ao vivo = Phase 3")

def get_client():
    if fonte == "Mock":
        return MockSplunkClient()
    if fonte == "Logs locais":
        return LocalLogClient()
    from splunk_client import SplunkClient
    return SplunkClient(settings.splunk)

# ===================== MAPA =====================
st.markdown("#### Threat Map")

me = my_location()
points = []

if me:
    points.append({
        "lat": me["lat"], "lon": me["lon"],
        "label": f"BASE · {me.get('city') or me.get('country')} · {me.get('ip')}",
        "color": [34, 211, 238],
        "radius": 40000,
    })

for p in st.session_state.get("threats", []):
    points.append(p)

if not points:
    points.append({
        "lat": 20, "lon": 0, "label": "Standby",
        "color": [40, 50, 70], "radius": 25000,
    })

df = pd.DataFrame(points)

halo = pdk.Layer(
    "ScatterplotLayer", data=df,
    get_position="[lon, lat]", get_fill_color="color",
    get_radius="radius", radius_scale=2.4, opacity=0.12, pickable=False,
)
core = pdk.Layer(
    "ScatterplotLayer", data=df,
    get_position="[lon, lat]", get_fill_color="color",
    get_radius="radius", opacity=0.92, pickable=True,
    stroked=True, get_line_color=[255, 255, 255, 50], line_width_min_pixels=1,
)

view = pdk.ViewState(
    latitude=me["lat"] if me else 15,
    longitude=me["lon"] if me else 10,
    zoom=1.35, pitch=38, bearing=0,
)
deck = pdk.Deck(
    layers=[halo, core],
    initial_view_state=view,
    tooltip={"html": "<b style='color:#22d3ee'>{label}</b>", "style": {"background": "#0f172a", "borderRadius": "12px", "padding": "8px 12px"}},
    map_style="dark",
)

st.markdown('<div class="map-frame">', unsafe_allow_html=True)
st.pydeck_chart(deck, use_container_width=True, height=400)
st.markdown("</div>", unsafe_allow_html=True)

if st.session_state.get("threats"):
    st.caption(f"{len(st.session_state.threats)} ameaca(s) plotada(s)  ·  ciano = sua base  ·  vermelho = origem suspeita")

# ===================== TRIAGEM =====================
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SEV_CSS = {"critical": "diag-critical", "high": "diag-high", "medium": "diag-medium", "low": "diag-low", "informational": "diag-info"}
PILL = {"critical": "pill-critical", "high": "pill-high", "medium": "pill-medium", "low": "pill-low", "informational": "pill-info"}

tab1, tab2 = st.tabs(["Triagem", "Investigacao"])

with tab1:
    if st.button("Executar Triagem", type="primary"):
        with st.spinner("Correlacionando sinais..."):
            client = get_client()
            analyst = AIAnalyst(settings.groq)
            alerts = client.get_alerts(count=count)

            results = []
            bar = st.progress(0)
            for i, a in enumerate(alerts):
                results.append(analyst.triage_alert(a))
                bar.progress((i + 1) / max(len(alerts), 1))
            bar.empty()

            # --- mapa: IPs → pontos vermelhos ---
            threats = []
            for ip in pull_ips(results):
                g = geo_lookup(ip)
                if not g:
                    continue
                sev = "high"
                for r in results:
                    if ip in str(r.raw_alert) or ip in str(r.indicators):
                        sev = str(r.severity).lower()
                        break
                threats.append({
                    "lat": g["lat"], "lon": g["lon"],
                    "label": f"THREAT · {ip} · {g.get('city') or g.get('country')} · {sev}",
                    "color": [239, 68, 68],
                    "radius": 22000,
                })
            st.session_state.threats = threats
            st.session_state.last_results = results

            # força redesenhar o mapa com os pontos novos
            st.rerun()

    # mostra resultados da última triagem (depois do rerun)
    results = st.session_state.get("last_results")
    if results:
        worst = sorted(results, key=lambda r: SEV_RANK.get(str(r.severity).lower(), 9))[0]
        sev = str(worst.severity).lower()

        st.markdown(f"""
        <div class="diag {SEV_CSS.get(sev, 'diag-info')}">
            <div class="diag-label">DIAGNOSTICO PRINCIPAL</div>
            <div class="diag-text">{worst.summary}</div>
            <div class="diag-meta">
                {worst.severity.upper()} · {worst.category} ·
                Estagio: {getattr(worst, 'attack_stage', '—')} ·
                Prioridade: {getattr(worst, 'priority_score', '—')} ·
                Escalar: {'SIM' if worst.escalate else 'nao'}
            </div>
        </div>
        """, unsafe_allow_html=True)

        actions = getattr(worst, "containment_actions", None) or []
        if actions:
            st.markdown("##### Contencao imediata")
            for a in actions:
                st.markdown(f"- `{a}`")

        esc = sum(1 for r in results if r.escalate)
        c1, c2, c3 = st.columns(3)
        c1.metric("Alertas", len(results))
        c2.metric("Escalonados", esc)
        c3.metric("IPs no mapa", len(st.session_state.get("threats", [])))

        st.markdown("---")
        st.markdown("#### Alertas classificados")

        for r in sorted(results, key=lambda x: SEV_RANK.get(str(x.severity).lower(), 9)):
            s = str(r.severity).lower()
            st.markdown(f"""
            <div class="alert-card {s}">
                <span class="sev-pill {PILL.get(s, 'pill-info')}">{r.severity.upper()}</span>
                <strong>{r.category}</strong>
                <div style="margin-top:0.5rem;color:#cbd5e1;font-size:0.95rem;">{r.summary}</div>
                <div style="margin-top:0.45rem;font-size:0.8rem;color:#64748b;">
                    FP: {r.false_positive_likelihood}% · Confianca: {r.confidence} ·
                    MITRE: {', '.join(r.mitre_attack) if r.mitre_attack else '—'}
                </div>
            </div>
            """, unsafe_allow_html=True)

            if r.recommended_actions:
                with st.expander("Acoes recomendadas"):
                    for a in r.recommended_actions:
                        st.markdown(f"- {a}")
            if getattr(r, "containment_actions", None):
                with st.expander("Contencao"):
                    for a in r.containment_actions:
                        st.markdown(f"- {a}")

with tab2:
    c1, c2 = st.columns(2)
    host = c1.text_input("Host", placeholder="10.0.0.5")
    user = c2.text_input("Usuario", placeholder="jdoe")
    if st.button("Investigar", type="primary"):
        if not host and not user:
            st.error("Informe host ou usuario")
        else:
            with st.spinner("Investigacao em curso..."):
                client = get_client()
                analyst = AIAnalyst(settings.groq)
                alert = {"host": host or None, "user": user or None, "note": "UI"}
                ctx = client.get_context_for_event(host=host or None, user=user or None)
                inv = analyst.investigate_incident(alert, ctx)
                report = rg.build_investigation_report(alert, inv)
                path = rg.save_report(report, settings.reports_dir, prefix="investigation")
                st.markdown(report)
                st.caption(path)