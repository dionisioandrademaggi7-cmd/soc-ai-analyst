import streamlit as st
import re
from config import settings
from mock_splunk_client import MockSplunkClient
from local_log_client import LocalLogClient
from ai_analyst import AIAnalyst
from containment import block_ip, unblock_ip
import report_generator as rg

st.set_page_config(page_title="SOC AI Analyst", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Barlow', sans-serif;
    background: #050505;
    color: #d4d4d4;
}
.stApp {
    background:
        repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,170,0.015) 2px, rgba(0,255,170,0.015) 4px),
        radial-gradient(ellipse 100% 80% at 50% -30%, rgba(0, 255, 170, 0.07), transparent 50%),
        #050505;
}

div[data-testid="stSidebar"] {
    background: #0a0a0a;
    border-right: 1px solid #1a1a1a;
}

.brand {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.35rem;
    color: #00ffaa;
    letter-spacing: 0.35em;
    text-transform: uppercase;
    margin-bottom: 0.15rem;
}
.brand-sub {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #4a4a4a;
    letter-spacing: 0.2em;
    margin-bottom: 1.5rem;
}

.panel {
    background: #0d0d0d;
    border: 1px solid #222;
    border-radius: 4px;
    padding: 1.25rem 1.4rem;
    margin-bottom: 1rem;
    position: relative;
}
.panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 3px; height: 100%;
    background: #00ffaa;
}

.panel-warn::before { background: #ff4444; }
.panel-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.25em;
    color: #00ffaa;
    margin-bottom: 0.75rem;
}
.panel-warn .panel-title { color: #ff6666; }

.sev {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 0.1em;
    padding: 0.15rem 0.5rem;
    border: 1px solid;
    display: inline-block;
    margin-right: 0.5rem;
}
.sev-critical { color: #ff4444; border-color: #ff4444; }
.sev-high { color: #ff8800; border-color: #ff8800; }
.sev-medium { color: #ffcc00; border-color: #ffcc00; }
.sev-low { color: #00ffaa; border-color: #00ffaa; }

.alert-row {
    background: #0a0a0a;
    border: 1px solid #1a1a1a;
    padding: 0.9rem 1rem;
    margin-bottom: 0.5rem;
    border-radius: 2px;
}

.stButton > button {
    font-family: 'Share Tech Mono', monospace !important;
    background: transparent !important;
    color: #00ffaa !important;
    border: 1px solid #00ffaa !important;
    border-radius: 2px !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    font-size: 0.75rem !important;
    padding: 0.55rem 1.4rem !important;
    transition: all 0.15s ease !important;
}
.stButton > button:hover {
    background: #00ffaa !important;
    color: #050505 !important;
    box-shadow: 0 0 20px rgba(0,255,170,0.35) !important;
}

div[data-testid="stMetric"] {
    background: #0d0d0d;
    border: 1px solid #1a1a1a;
    padding: 0.6rem 0.9rem;
    border-radius: 2px;
}

h1,h2,h3,h4 { font-family: 'Barlow', sans-serif !important; color: #e5e5e5 !important; }
hr { border-color: #1a1a1a; }
code { color: #00ffaa !important; }
</style>
""", unsafe_allow_html=True)

# ---------- header ----------
st.markdown('<div class="brand">SOC AI ANALYST</div>', unsafe_allow_html=True)
st.markdown('<div class="brand-sub">detect · triage · contain</div>', unsafe_allow_html=True)

with st.sidebar:
    st.markdown("#### SOURCE")
    fonte = st.radio("fonte", ["Mock", "Logs locais", "Splunk"], index=0, label_visibility="collapsed")
    count = st.slider("Alertas", 1, 20, 5)
    st.markdown("---")
    st.caption("PHASE 3 · CONTAINMENT")

def get_client():
    if fonte == "Mock":
        return MockSplunkClient()
    if fonte == "Logs locais":
        return LocalLogClient()
    from splunk_client import SplunkClient
    return SplunkClient(settings.splunk)

def pull_ips(results):
    found = []
    for r in results:
        blob = str(r.raw_alert) + " " + " ".join(str(x) for x in (r.indicators or []))
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
            found.append(m)
    return list(dict.fromkeys(found))

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

tab1, tab2, tab3 = st.tabs(["TRIAGE", "INVESTIGATE", "CONTAIN"])

# ========== TRIAGE ==========
with tab1:
    if st.button("RUN TRIAGE", key="triage_btn"):
        with st.spinner("analyzing..."):
            client = get_client()
            analyst = AIAnalyst(settings.groq)
            alerts = client.get_alerts(count=count)
            results = []
            bar = st.progress(0)
            for i, a in enumerate(alerts):
                results.append(analyst.triage_alert(a))
                bar.progress((i + 1) / max(len(alerts), 1))
            bar.empty()
            st.session_state["results"] = results
            st.session_state["threat_ips"] = pull_ips(results)

    results = st.session_state.get("results")
    if results:
        worst = sorted(results, key=lambda r: SEV_RANK.get(str(r.severity).lower(), 9))[0]
        sev = str(worst.severity).lower()

        st.markdown(f"""
        <div class="panel panel-warn">
            <div class="panel-title">PRIMARY DIAGNOSIS</div>
            <div style="font-size:1.05rem;font-weight:600;color:#f5f5f5;margin-bottom:0.5rem;">{worst.summary}</div>
            <span class="sev sev-{sev if sev in ('critical','high','medium','low') else 'low'}">{worst.severity.upper()}</span>
            <span style="color:#888;font-size:0.85rem;">{worst.category} · stage: {getattr(worst,'attack_stage','—')} · escalate: {'YES' if worst.escalate else 'no'}</span>
        </div>
        """, unsafe_allow_html=True)

        acts = getattr(worst, "containment_actions", None) or []
        if acts:
            st.markdown('<div class="panel"><div class="panel-title">SUGGESTED CONTAINMENT</div>', unsafe_allow_html=True)
            for a in acts:
                st.markdown(f"`{a}`")
            st.markdown("</div>", unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        c1.metric("ALERTS", len(results))
        c2.metric("ESCALATED", sum(1 for r in results if r.escalate))
        c3.metric("IPS FOUND", len(st.session_state.get("threat_ips", [])))

        st.markdown("---")
        for r in sorted(results, key=lambda x: SEV_RANK.get(str(x.severity).lower(), 9)):
            s = str(r.severity).lower()
            st.markdown(f"""
            <div class="alert-row">
                <span class="sev sev-{s if s in ('critical','high','medium','low') else 'low'}">{r.severity.upper()}</span>
                <strong style="color:#ddd">{r.category}</strong>
                <div style="margin-top:0.4rem;color:#aaa;font-size:0.9rem;">{r.summary}</div>
            </div>
            """, unsafe_allow_html=True)

# ========== INVESTIGATE ==========
with tab2:
    col1, col2 = st.columns(2)
    host = col1.text_input("HOST", placeholder="10.0.0.5")
    user = col2.text_input("USER", placeholder="jdoe")
    if st.button("RUN INVESTIGATION", key="inv_btn"):
        if not host and not user:
            st.error("Informe host ou user")
        else:
            with st.spinner("investigating..."):
                client = get_client()
                analyst = AIAnalyst(settings.groq)
                alert = {"host": host or None, "user": user or None, "note": "UI"}
                ctx = client.get_context_for_event(host=host or None, user=user or None)
                inv = analyst.investigate_incident(alert, ctx)
                path = rg.save_report(rg.build_investigation_report(alert, inv), settings.reports_dir, prefix="investigation")
                st.markdown(f'<div class="panel"><div class="panel-title">REPORT</div></div>', unsafe_allow_html=True)
                st.markdown(inv)
                st.caption(path)

# ========== CONTAIN ==========
with tab3:
    st.markdown("""
    <div class="panel panel-warn">
        <div class="panel-title">CONTAINMENT AGENT</div>
        <div style="color:#999;font-size:0.9rem;">
            Bloqueio local via ufw. Dry-run por padrao. Use EXECUTE so no lab Ubuntu com ufw ativo.
            Localhost e IPs de whitelist nunca sao bloqueados.
        </div>
    </div>
    """, unsafe_allow_html=True)

    ips = st.session_state.get("threat_ips", [])
    if ips:
        st.markdown("**IPs extraidos da ultima triagem:**")
        st.code(", ".join(ips))

    ip_in = st.text_input("TARGET IP", placeholder="203.0.113.5", value=ips[0] if ips else "")
    c1, c2, c3 = st.columns(3)

    with c1:
        if st.button("SIMULATE BLOCK", key="dry_block"):
            if not ip_in.strip():
                st.error("Informe um IP")
            else:
                r = block_ip(ip_in.strip(), dry_run=True)
                st.info(f"[DRY-RUN] {r.message}")

    with c2:
        confirm = st.checkbox("Confirmo bloqueio real", key="confirm_block")
        if st.button("EXECUTE BLOCK", key="live_block"):
            if not ip_in.strip():
                st.error("Informe um IP")
            elif not confirm:
                st.warning("Marque a confirmacao")
            else:
                r = block_ip(ip_in.strip(), dry_run=False)
                if r.success:
                    st.success(f"[LIVE] {r.message}")
                else:
                    st.error(f"[LIVE] {r.message}")

    with c3:
        if st.button("UNBLOCK (DRY)", key="dry_unblock"):
            if not ip_in.strip():
                st.error("Informe um IP")
            else:
                r = unblock_ip(ip_in.strip(), dry_run=True)
                st.info(f"[DRY-RUN] {r.message}")

    st.caption("Log em reports/containment_actions.log")