import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from database.db import init_db
from config import GROQ_API_KEY, OPENAI_API_KEY

st.set_page_config(
    page_title="Traffic Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

st.markdown("""
<style>
    .main .block-container { padding-top: 1rem; max-width: 100%; }
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #0f3460;
        border-radius: 10px;
        padding: 15px;
        color: #e0e0e0;
    }
    div[data-testid="stMetric"] label { color: #a0aec0 !important; font-size: 0.85rem !important; }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] { color: #00d4ff !important; font-size: 1.8rem !important; }
    .severity-critical { background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .severity-high { background: #ea580c; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .severity-suspicious { background: #ca8a04; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .severity-low { background: #65a30d; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .severity-normal { background: #16a34a; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .stAlert { border-radius: 8px; }
    .block-container { padding-top: 1rem !important; }
</style>
""", unsafe_allow_html=True)


def main():
    with st.sidebar:
        st.markdown("## 🛡️ TRAFFIC SENTINEL")
        st.markdown("---")
        page = st.radio(
            "Navigation",
            ["🏠 Dashboard", "📡 Live Traffic", "🚨 Alerts",
             "🔎 Investigations", "🕐 Timeline", "🕸️ Network Graph",
             "🤖 AI Analyst", "🔄 Security Scan", "🎮 Simulation", "⚙️ Settings"],
            label_visibility="collapsed",
        )

        st.markdown("---")
        if GROQ_API_KEY:
            st.success("AI active (Groq / Llama)")
        elif OPENAI_API_KEY:
            st.success("AI active (OpenAI)")
        else:
            st.warning("AI features require GROQ_API_KEY")

    if page == "🏠 Dashboard":
        render_dashboard()
    elif page == "📡 Live Traffic":
        render_live_traffic()
    elif page == "🚨 Alerts":
        render_alerts()
    elif page == "🔎 Investigations":
        render_investigations()
    elif page == "🕐 Timeline":
        render_timeline()
    elif page == "🕸️ Network Graph":
        render_network_graph()
    elif page == "🤖 AI Analyst":
        render_ai_analyst()
    elif page == "🔄 Security Scan":
        render_security_scan()
    elif page == "🎮 Simulation":
        render_simulation()
    elif page == "⚙️ Settings":
        render_settings()


def render_dashboard():
    from database.db import get_stats, query_flows, query_alerts
    from analytics.statistics import (
        get_protocol_distribution, get_alert_severity_distribution,
        get_top_destinations, get_risk_distribution,
    )
    from detection.risk_engine import get_risk_color
    import plotly.graph_objects as go
    import plotly.express as px

    st.markdown("# 🛡️ TRAFFIC SENTINEL — Dashboard")
    st.markdown("### AI Network Traffic Analyzer & Threat Investigator")
    st.markdown("---")

    stats = get_stats()

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("FLOWS", f"{stats['total_flows']:,}")
    with col2:
        st.metric("ALERTS", f"{stats['total_alerts']:,}")
    with col3:
        st.metric("CRITICAL", f"{stats['critical_alerts']:,}")
    with col4:
        st.metric("HIGH RISK", f"{stats['high_alerts']:,}")
    with col5:
        st.metric("ANOMALIES", f"{stats['anomalies']:,}")

    st.markdown("---")

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### Alert Severity Distribution")
        severity_data = get_alert_severity_distribution()
        if severity_data:
            labels = [d["severity"] for d in severity_data]
            values = [d["count"] for d in severity_data]
            color_map = {
                "Critical": "#dc2626", "High": "#ea580c",
                "Suspicious": "#ca8a04", "Low": "#65a30d", "Normal": "#16a34a",
            }
            fig = go.Figure(data=[go.Pie(
                labels=labels, values=values,
                marker=dict(colors=[color_map.get(l, "#6b7280") for l in labels]),
                hole=0.4,
            )])
            fig.update_layout(
                height=300, margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts yet. Run a simulation to generate data.")

    with col_b:
        st.markdown("#### Protocol Distribution")
        proto_data = get_protocol_distribution()
        if proto_data:
            labels = [d["protocol"] or "Unknown" for d in proto_data]
            values = [d["count"] for d in proto_data]
            fig = go.Figure(data=[go.Bar(
                x=labels, y=values,
                marker_color=["#00d4ff", "#7c3aed", "#f59e0b", "#10b981"],
            )])
            fig.update_layout(
                height=300, margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
                xaxis=dict(gridcolor="#333"), yaxis=dict(gridcolor="#333"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No traffic data yet.")

    col_c, col_d = st.columns(2)

    with col_c:
        st.markdown("#### Risk Score Distribution")
        risk_data = get_risk_distribution()
        if risk_data:
            labels = [d["category"] for d in risk_data]
            values = [d["count"] for d in risk_data]
            color_map = {
                "Normal": "#16a34a", "Low": "#65a30d",
                "Suspicious": "#ca8a04", "High": "#ea580c", "Critical": "#dc2626",
            }
            fig = go.Figure(data=[go.Bar(
                x=labels, y=values,
                marker=[color_map.get(l, "#6b7280") for l in labels],
            )])
            fig.update_layout(
                height=300, margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
                xaxis=dict(gridcolor="#333"), yaxis=dict(gridcolor="#333"),
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_d:
        st.markdown("#### Top Destinations")
        top_dest = get_top_destinations(8)
        if top_dest:
            dest_data = []
            for d in top_dest:
                risk_color = get_risk_color(
                    "High" if d["avg_risk"] > 60 else "Suspicious" if d["avg_risk"] > 40 else "Normal"
                )
                dest_data.append({
                    "IP": d["destination_ip"],
                    "Connections": d["connection_count"],
                    "Avg Risk": f"{d['avg_risk']:.0f}",
                })
            st.dataframe(dest_data, use_container_width=True, hide_index=True)
        else:
            st.info("No destination data yet.")

    st.markdown("---")
    st.markdown("#### Recent Flows")
    flows = query_flows(limit=10)
    if flows:
        display_flows = []
        for f in flows:
            display_flows.append({
                "Time": f["timestamp"][:19],
                "Source": f["source_ip"],
                "Dest": f["destination_ip"],
                "Port": f.get("destination_port", "-"),
                "Protocol": f.get("protocol", "-"),
                "Bytes": f"{f.get('bytes_sent', 0) + f.get('bytes_received', 0):,}",
                "Risk": f"{f.get('risk_score', 0):.0f}",
                "Status": f.get("status", "normal"),
            })
        st.dataframe(display_flows, use_container_width=True, hide_index=True)
    else:
        st.info("No traffic recorded yet. Go to Simulation to generate sample data.")


def render_live_traffic():
    from database.db import query_flows
    import plotly.graph_objects as go

    st.markdown("# 📡 Live Traffic Monitor")
    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    with col1:
        filter_ip = st.text_input("Filter by IP", "")
    with col2:
        filter_protocol = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP"])
    with col3:
        filter_risk = st.slider("Min Risk Score", 0, 100, 0)

    protocol = filter_protocol if filter_protocol != "All" else None
    flows = query_flows(
        limit=200,
        source_ip=filter_ip if filter_ip else None,
        destination_ip=filter_ip if filter_ip else None,
        protocol=protocol,
        min_risk=filter_risk,
    )

    st.markdown(f"**{len(flows)} flows found**")

    if flows:
        display = []
        for f in flows:
            risk = f.get("risk_score", 0)
            if risk > 80:
                status_badge = "🔴"
            elif risk > 60:
                status_badge = "🟠"
            elif risk > 40:
                status_badge = "🟡"
            else:
                status_badge = "🟢"
            display.append({
                "Time": f["timestamp"][:19],
                "Source": f["source_ip"],
                "Destination": f["destination_ip"],
                "Src Port": f.get("source_port", "-"),
                "Dst Port": f.get("destination_port", "-"),
                "Protocol": f.get("protocol", "-"),
                "Packets": f.get("packet_count", 0),
                "Bytes": f"{f.get('bytes_sent', 0) + f.get('bytes_received', 0):,}",
                "Duration": f"{f.get('duration', 0):.2f}s",
                "Risk": f"{risk:.0f}",
                "Status": f"{status_badge} {f.get('status', 'normal')}",
            })
        st.dataframe(display, use_container_width=True, hide_index=True)

        if flows:
            st.markdown("#### Traffic Volume Over Time")
            times = [f["timestamp"][:19] for f in reversed(flows)]
            volumes = [f.get("bytes_sent", 0) + f.get("bytes_received", 0) for f in reversed(flows)]
            risks = [f.get("risk_score", 0) for f in reversed(flows)]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=times, y=volumes, mode="lines+markers",
                name="Volume (bytes)", line=dict(color="#00d4ff", width=2),
            ))
            fig.add_trace(go.Scatter(
                x=times, y=risks, mode="lines", name="Risk Score",
                line=dict(color="#ef4444", width=2, dash="dash"),
                yaxis="y2",
            ))
            fig.update_layout(
                height=300, margin=dict(t=20, b=20),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
                xaxis=dict(gridcolor="#333"), yaxis=dict(gridcolor="#333", title="Bytes"),
                yaxis2=dict(title="Risk", overlaying="y", side="right"),
                legend=dict(orientation="h", y=-0.2),
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No traffic matches your filters.")


def render_alerts():
    from database.db import query_alerts
    from detection.risk_engine import get_risk_color

    st.markdown("# 🚨 Security Alerts")
    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    with col1:
        filter_severity = st.selectbox("Severity", ["All", "Critical", "High", "Suspicious", "Low", "Normal"])
    with col2:
        filter_status = st.selectbox("Status", ["All", "Open", "Investigating", "Resolved"])
    with col3:
        st.markdown("")
        st.markdown("")

    severity = filter_severity if filter_severity != "All" else None
    status = filter_status if filter_status != "All" else None
    alerts = query_alerts(limit=100, severity=severity, status=status)

    if not alerts:
        st.info("No alerts match your filters.")
        return

    st.markdown(f"**{len(alerts)} alerts**")

    severity_counts = {}
    for a in alerts:
        s = a.get("severity", "Normal")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    cols = st.columns(5)
    for i, (sev, count) in enumerate(severity_counts.items()):
        if i < 5:
            color = get_risk_color(sev)
            cols[i].markdown(
                f'<div style="text-align:center; background:{color}22; border:1px solid {color}; '
                f'border-radius:8px; padding:10px;">'
                f'<div style="font-size:0.8rem; color:{color};">{sev}</div>'
                f'<div style="font-size:1.5rem; font-weight:bold; color:{color};">{count}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")

    for alert in alerts:
        severity = alert.get("severity", "Normal")
        color = get_risk_color(severity)
        with st.expander(
            f"**{alert.get('alert_type', 'Unknown')}** | "
            f"Risk: {alert.get('risk_score', 0):.0f} | "
            f"{alert.get('source_ip', '?')} → {alert.get('destination_ip', '?')} | "
            f"{alert.get('timestamp', '')[:19]}"
        ):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"**Alert ID:** {alert['id']}")
                st.markdown(f"**Type:** {alert.get('alert_type', 'N/A')}")
                st.markdown(f"**Severity:** :{color}[{severity}]")
            with col2:
                st.markdown(f"**Source:** {alert.get('source_ip', 'N/A')}")
                st.markdown(f"**Destination:** {alert.get('destination_ip', 'N/A')}")
                st.markdown(f"**Port:** {alert.get('destination_port', 'N/A')}")
            with col3:
                st.markdown(f"**Protocol:** {alert.get('protocol', 'N/A')}")
                st.markdown(f"**Risk Score:** {alert.get('risk_score', 0):.0f}/100")
                st.markdown(f"**Confidence:** {alert.get('confidence', 0):.0%}")

            st.markdown("**Detection Reasons:**")
            reasons = alert.get("detection_reasons", "")
            if reasons:
                for reason in reasons.split(";"):
                    if reason.strip():
                        st.markdown(f"- {reason.strip()}")

            col_a, col_b = st.columns(2)
            with col_a:
                if st.button(f"🤖 Explain Alert {alert['id']}", key=f"explain_{alert['id']}"):
                    from ai.security_agent import SecurityAnalyst
                    analyst = SecurityAnalyst()
                    with st.spinner("AI analyzing..."):
                        explanation = analyst.explain_alert(alert)
                    st.markdown("### 🤖 AI Explanation")
                    st.markdown(explanation)

            with col_b:
                if st.button(f"🧐 Challenge Conclusion {alert['id']}", key=f"skeptic_{alert['id']}"):
                    from ai.security_agent import SecurityAnalyst
                    analyst = SecurityAnalyst()
                    with st.spinner("Challenging conclusion..."):
                        challenge = analyst.skeptic_analysis(
                            alert.get("explanation", "Suspicious activity"),
                            alert, [],
                        )
                    st.markdown("### 🧐 Skeptic Analysis")
                    st.markdown(challenge)


def render_investigations():
    from database.db import get_db, create_investigation, insert_evidence

    st.markdown("# 🔎 Investigations")
    st.markdown("---")

    with get_db() as conn:
        cases = conn.execute(
            "SELECT * FROM investigations ORDER BY created_at DESC"
        ).fetchall()
        cases = [dict(c) for c in cases]

    tab1, tab2 = st.tabs(["Open Cases", "Create New Case"])

    with tab1:
        if cases:
            for case in cases:
                status_color = {"open": "#f59e0b", "closed": "#22c55e"}.get(case["status"], "#6b7280")
                with st.expander(
                    f"**{case['case_name']}** | Status: {case['status']} | Created: {case['created_at'][:10]}"
                ):
                    st.markdown(f"**Case ID:** {case['id']}")
                    st.markdown(f"**Confidence:** {case.get('confidence', 0):.0%}")
                    if case.get("conclusion"):
                        st.markdown(f"**Conclusion:** {case['conclusion']}")

                    evidence_rows = conn.execute(
                        "SELECT * FROM evidence WHERE investigation_id = ?", (case["id"],)
                    ).fetchall()
                    if evidence_rows:
                        st.markdown("**Evidence:**")
                        for ev in evidence_rows:
                            st.markdown(f"- [{ev['evidence_type']}] {ev['description']}")
        else:
            st.info("No investigations yet. Create one below.")

    with tab2:
        with st.form("new_case"):
            case_name = st.text_input("Case Name", placeholder="e.g., Suspicious Activity from 192.168.1.50")
            evidence_desc = st.text_area("Initial Evidence (optional)", placeholder="Describe what triggered this investigation...")
            submitted = st.form_submit_button("Create Investigation")
            if submitted and case_name:
                case_id = create_investigation(case_name)
                if evidence_desc:
                    insert_evidence(case_id, "user_note", evidence_desc, "manual_input", "unverified")
                st.success(f"Case #{case_id} created!")
                st.rerun()


def render_timeline():
    from database.db import query_flows, query_alerts

    st.markdown("# 🕐 Event Timeline")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        filter_host = st.text_input("Filter by Host IP", "")
    with col2:
        filter_severity = st.selectbox("Min Severity", ["All", "Low", "Suspicious", "High", "Critical"])

    severity_order = {"All": 0, "Low": 1, "Suspicious": 2, "High": 3, "Critical": 4}
    min_severity = severity_order.get(filter_severity, 0)

    flows = query_flows(limit=200, source_ip=filter_host if filter_host else None)
    alerts = query_alerts(limit=200)

    events = []
    for f in flows:
        risk = f.get("risk_score", 0)
        if risk > 80:
            sev = "Critical"
        elif risk > 60:
            sev = "High"
        elif risk > 40:
            sev = "Suspicious"
        elif risk > 20:
            sev = "Low"
        else:
            sev = "Normal"

        events.append({
            "timestamp": f["timestamp"],
            "type": "Flow",
            "description": f"{f['source_ip']} → {f['destination_ip']}:{f.get('destination_port', '?')} ({f.get('protocol', '?')})",
            "severity": sev,
            "risk_score": f.get("risk_score", 0),
        })

    for a in alerts:
        events.append({
            "timestamp": a["timestamp"],
            "type": a.get("alert_type", "Alert"),
            "description": f"{a.get('source_ip', '?')} → {a.get('destination_ip', '?')}: {a.get('alert_type', 'Unknown')}",
            "severity": a.get("severity", "Normal"),
            "risk_score": a.get("risk_score", 0),
        })

    events.sort(key=lambda x: x["timestamp"], reverse=True)
    events = [e for e in events if severity_order.get(e["severity"], 0) >= min_severity]

    st.markdown(f"**{len(events)} events**")

    if events:
        import plotly.graph_objects as go
        times = [e["timestamp"][:19] for e in events[:50]]
        risks = [e["risk_score"] for e in events[:50]]
        types = [e["type"] for e in events[:50]]

        color_map = {
            "Critical": "#dc2626", "High": "#ea580c",
            "Suspicious": "#ca8a04", "Low": "#65a30d", "Normal": "#16a34a",
        }
        colors = [color_map.get(e["severity"], "#6b7280") for e in events[:50]]

        fig = go.Figure(data=[go.Scatter(
            x=times, y=risks, mode="markers",
            marker=dict(size=10, color=colors),
            text=types, hovertemplate="%{x}<br>%{text}<br>Risk: %{y}",
        )])
        fig.update_layout(
            height=300, margin=dict(t=20, b=20),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            xaxis=dict(gridcolor="#333", title="Time"),
            yaxis=dict(gridcolor="#333", title="Risk Score"),
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        for event in events[:30]:
            color = color_map.get(event["severity"], "#6b7280")
            st.markdown(
                f'<div style="display:flex; align-items:center; padding:8px; margin:4px 0; '
                f'border-left:3px solid {color}; background:#1a1a2e; border-radius:4px;">'
                f'<span style="color:#888; width:160px; font-size:0.85rem;">{event["timestamp"][:19]}</span>'
                f'<span style="color:{color}; font-weight:bold; width:100px;">{event["severity"]}</span>'
                f'<span style="color:#e0e0e0;">{event["description"]}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


def render_network_graph():
    from database.db import get_db

    st.markdown("# 🕸️ Network Relationship Graph")
    st.markdown("---")

    try:
        import networkx as nx
        import plotly.graph_objects as go
        HAS_NX = True
    except ImportError:
        HAS_NX = False
        st.warning("NetworkX not installed. Run: pip install networkx")
        return

    G = nx.DiGraph()

    with get_db() as conn:
        relationships = conn.execute(
            """SELECT r.*, e1.type as src_type, e1.value as src_value,
                      e2.type as tgt_type, e2.value as tgt_value
            FROM relationships r
            JOIN entities e1 ON r.source_entity_id = e1.id
            JOIN entities e2 ON r.target_entity_id = e2.id
            LIMIT 100"""
        ).fetchall()

    if not relationships:
        st.info("No entity relationships yet. Run a simulation to generate data.")
        return

    for r in relationships:
        src_label = f"{r['src_type']}:{r['src_value']}"
        tgt_label = f"{r['tgt_type']}:{r['tgt_value']}"
        G.add_node(src_label, type=r["src_type"], value=r["src_value"])
        G.add_node(tgt_label, type=r["tgt_type"], value=r["tgt_value"])
        G.add_edge(src_label, tgt_label, relationship=r["relationship"])

    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_text = list(G.nodes())
    node_colors = []
    for n in G.nodes():
        ntype = G.nodes[n].get("type", "")
        if ntype == "ip":
            node_colors.append("#00d4ff")
        elif ntype == "domain":
            node_colors.append("#f59e0b")
        else:
            node_colors.append("#7c3aed")

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=1, color="#4a5568"), hoverinfo="none",
    ))
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=15, color=node_colors, line=dict(width=1, color="white")),
        text=node_text, textposition="top center",
        hovertext=node_text, hoverinfo="text",
    ))
    fig.update_layout(
        height=600, margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.markdown("**Relationships:**")
    for r in relationships:
        st.markdown(
            f"- **{r['src_value']}** `{r['relationship']}` **{r['tgt_value']}**"
        )


def render_ai_analyst():
    from ai.security_agent import SecurityAnalyst
    from database.db import query_alerts

    st.markdown("# 🤖 AI Security Analyst")
    st.markdown("---")

    analyst = SecurityAnalyst()
    if not analyst.available:
        st.warning("AI features require GROQ_API_KEY. Configure in .env file.")
        st.info("You can still use the dashboard, simulation, and detection features.")
        return

    tab1, tab2, tab3 = st.tabs(["💬 Chat", "🔗 Event Correlation", "📊 Report Generation"])

    with tab1:
        st.markdown("### Ask the AI Security Analyst")
        st.markdown("Ask questions about traffic, alerts, or security events.")

        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []

        for msg in st.session_state.chat_history:
            role = "🧑 You" if msg["role"] == "user" else "🤖 AI Analyst"
            st.markdown(f"**{role}:** {msg['content']}")

        user_input = st.text_input("Your question:", placeholder="e.g., Have we seen IP 192.168.1.50 before?")
        if st.button("Send") and user_input:
            st.session_state.chat_history.append({"role": "user", "content": user_input})
            with st.spinner("AI analyzing..."):
                response = analyst.chat(user_input)
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()

    with tab2:
        st.markdown("### Event Correlation")
        alerts = query_alerts(limit=20)
        if not alerts:
            st.info("No alerts available for correlation.")
            return

        selected = st.multiselect(
            "Select alerts to correlate",
            options=[f"Alert {a['id']}: {a['alert_type']}" for a in alerts],
        )
        if selected and st.button("🔍 Correlate Events"):
            selected_ids = [int(s.split(":")[0].replace("Alert ", "")) for s in selected]
            selected_alerts = [a for a in alerts if a["id"] in selected_ids]
            with st.spinner("AI correlating events..."):
                correlation = analyst.correlate_events(selected_alerts)
            st.markdown("### Correlation Analysis")
            st.markdown(correlation)

    with tab3:
        st.markdown("### Generate Investigation Report")
        from database.db import get_db
        with get_db() as conn:
            cases = conn.execute("SELECT * FROM investigations").fetchall()
        if not cases:
            st.info("No investigations. Create one first.")
            return

        case_options = {f"{c['case_name']} (#{c['id']})": c["id"] for c in cases}
        selected_case = st.selectbox("Select case", list(case_options.keys()))
        if selected_case and st.button("📄 Generate Report"):
            case_id = case_options[selected_case]
            from ai.tools import get_investigation_evidence
            case_data = dict([c for c in cases if c["id"] == case_id][0])
            evidence_data = get_investigation_evidence(case_id)
            with st.spinner("AI generating report..."):
                report = analyst.generate_report(
                    case_data, evidence_data.get("evidence", []),
                    [],
                )
            st.markdown(report)


def render_security_scan():
    from analytics.statistics import compare_periods

    st.markdown("# 🔄 Security Health Scan")
    st.markdown("---")
    st.markdown("Compare network security posture between two periods.")

    days = st.selectbox("Comparison Period", [7, 15, 30], index=1)

    if st.button("🔍 Run Health Scan"):
        with st.spinner("Analyzing periods..."):
            comparison = compare_periods(days)

        current = comparison.get("current", {})
        previous = comparison.get("previous", {})

        st.markdown(f"## Security Health Report — Last {days} Days")
        st.markdown("---")

        def delta_text(curr, prev):
            if prev == 0:
                return "N/A"
            diff = curr - prev
            pct = (diff / prev * 100) if prev else 0
            arrow = "↑" if diff > 0 else "↓" if diff < 0 else "→"
            color = "#ef4444" if diff > 0 else "#22c55e" if diff < 0 else "#6b7280"
            return f'<span style="color:{color}">{arrow} {abs(pct):.1f}%</span>'

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            curr_flows = current.get("flows", 0)
            prev_flows = previous.get("flows", 0)
            st.metric("Traffic Flows", f"{curr_flows:,}", delta_text(curr_flows, prev_flows), delta_color="inverse")
        with col2:
            curr_alerts = comparison.get("current_alerts", 0)
            prev_alerts = comparison.get("previous_alerts", 0)
            st.metric("Alerts", f"{curr_alerts}", delta_text(curr_alerts, prev_alerts), delta_color="inverse")
        with col3:
            curr_risk = current.get("avg_risk", 0)
            prev_risk = previous.get("avg_risk", 0)
            st.metric("Avg Risk Score", f"{curr_risk:.1f}", delta_text(curr_risk, prev_risk), delta_color="inverse")
        with col4:
            curr_hosts = current.get("hosts", 0)
            prev_hosts = previous.get("hosts", 0)
            st.metric("Active Hosts", f"{curr_hosts}", delta_text(curr_hosts, prev_hosts), delta_color="inverse")

        st.markdown("---")
        st.markdown("### 🤖 AI Health Summary")
        from ai.security_agent import SecurityAnalyst
        analyst = SecurityAnalyst()
        if analyst.available:
            with st.spinner("AI generating summary..."):
                summary = analyst.chat(
                    f"Summarize this network security health comparison:\n"
                    f"Current period: {curr_flows} flows, {curr_alerts} alerts, avg risk {curr_risk:.1f}\n"
                    f"Previous period: {prev_flows} flows, {prev_alerts} alerts, avg risk {prev_risk:.1f}\n"
                    f"Provide a brief, factual security health assessment."
                )
            st.markdown(summary)
        else:
            st.info("AI summary requires GROQ_API_KEY.")


def render_simulation():
    from simulation.scenarios import SCENARIO_GENERATORS
    from simulation.simulator import run_simulation
    from database.db import clear_all_data

    st.markdown("# 🎮 Simulation Mode")
    st.markdown("---")
    st.markdown("Generate synthetic traffic scenarios to test the detection engine.")

    st.markdown("### Available Scenarios")

    scenario_descriptions = {
        "Normal Traffic": ("🟢", "Typical web browsing, DNS queries, and application traffic."),
        "Port Scan": ("🔴", "One host rapidly contacting many ports on a target — reconnaissance pattern."),
        "High Connection Frequency": ("🟠", "Unusually high number of connections in a short period."),
        "DNS Anomaly": ("🟡", "Queries to suspicious domains with unusual TLDs."),
        "Unusual Outbound Traffic": ("🔴", "Large data transfers to known suspicious IPs."),
        "Brute Force Pattern": ("🟠", "Repeated failed connection attempts to authentication ports."),
    }

    cols = st.columns(3)
    for i, (name, (icon, desc)) in enumerate(scenario_descriptions.items()):
        with cols[i % 3]:
            st.markdown(
                f'<div style="background:#1a1a2e; border:1px solid #333; border-radius:8px; padding:12px; margin:4px 0;">'
                f'<div style="font-size:1.1rem; font-weight:bold;">{icon} {name}</div>'
                f'<div style="font-size:0.85rem; color:#aaa;">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")

    col1, col2 = st.columns([2, 1])
    with col1:
        scenario = st.selectbox("Select Scenario", list(SCENARIO_GENERATORS.keys()))
    with col2:
        st.markdown("")
        st.markdown("")
        run_btn = st.button("▶️ Run Simulation", type="primary", use_container_width=True)

    if run_btn:
        with st.spinner(f"Generating {scenario} traffic..."):
            result = run_simulation(scenario)

        if "error" in result:
            st.error(result["error"])
        else:
            st.success(
                f"Generated {result['flows_processed']} flows, "
                f"{result['alerts_generated']} alerts"
            )

            if result["alerts"]:
                st.markdown("### Generated Alerts")
                for alert in result["alerts"]:
                    sev = alert.get("severity", "Normal")
                    color_map = {
                        "Critical": "#dc2626", "High": "#ea580c",
                        "Suspicious": "#ca8a04", "Low": "#65a30d", "Normal": "#16a34a",
                    }
                    color = color_map.get(sev, "#6b7280")
                    st.markdown(
                        f'<div style="background:#1a1a2e; border-left:4px solid {color}; '
                        f'padding:10px; margin:5px 0; border-radius:4px;">'
                        f'<span style="font-weight:bold; color:{color};">{sev}</span> — '
                        f'{alert.get("alert_type", "Unknown")} | '
                        f'{alert.get("source_ip", "?")} → {alert.get("destination_ip", "?")} | '
                        f'Risk: {alert.get("risk_score", 0):.0f}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No alerts generated for this scenario.")

    st.markdown("---")
    if st.button("🗑️ Clear All Data", type="secondary"):
        clear_all_data()
        st.success("All data cleared.")
        st.rerun()


def render_settings():
    st.markdown("# ⚙️ Settings")
    st.markdown("---")

    st.markdown("### Environment Configuration")
    st.code("""
# .env file contents:
GROQ_API_KEY=your-key-here
GROQ_MODEL=qwen/qwen3.8-27b
THREAT_INTEL_API_KEY=optional-key
    """)

    st.markdown("### Detection Thresholds")
    from config import DETECTION_CONFIG, RISK_WEIGHTS, RISK_THRESHOLDS

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Risk Thresholds:**")
        for level, (low, high) in RISK_THRESHOLDS.items():
            st.markdown(f"- {level.capitalize()}: {low}–{high}")

    with col2:
        st.markdown("**Risk Weights:**")
        for rule, weight in RISK_WEIGHTS.items():
            st.markdown(f"- {rule}: +{weight}")

    st.markdown("### Detection Config")
    for key, value in DETECTION_CONFIG.items():
        st.markdown(f"- **{key}:** {value}")

    st.markdown("### Tech Stack")
    st.markdown("""
    - **Backend:** Python
    - **Database:** SQLite
    - **Packet Capture:** Scapy (optional)
    - **ML:** scikit-learn (Isolation Forest)
    - **AI:** OpenAI GPT API
    - **Dashboard:** Streamlit
    - **Charts:** Plotly
    - **Reports:** ReportLab
    - **Graphs:** NetworkX
    """)


if __name__ == "__main__":
    main()
