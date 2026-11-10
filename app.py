"""PQC Security Monitoring Dashboard — migration to ML-KEM.

Run:  pip install streamlit plotly pandas
      streamlit run app.py
All data is synthetic.
"""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="PQC Security Monitor", page_icon="🔐", layout="wide")

# ----------------------------- Mock data ------------------------------------
DEPARTMENTS = ["Finance", "HR", "R&D", "Legal", "Operations"]
RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
RISK_COLORS = {"Low": "#2e9e6b", "Medium": "#e0b020", "High": "#e8742a", "Critical": "#d13438"}

assets = pd.DataFrame(
    [
        # asset, department, sensitivity (0-100), shelf life (yrs), exposure risk (0-100), level
        ("Customer PII Vault", "Finance", 95, 25, 91, "Critical"),
        ("Payment Card Archive", "Finance", 92, 10, 78, "High"),
        ("M&A Deal Documents", "Finance", 88, 15, 72, "High"),
        ("Employee Health Records", "HR", 90, 30, 87, "Critical"),
        ("Payroll & Tax Data", "HR", 80, 10, 55, "Medium"),
        ("Background Checks", "HR", 70, 7, 38, "Medium"),
        ("Chip Design IP", "R&D", 98, 30, 95, "Critical"),
        ("Pharma Trial Data", "R&D", 94, 25, 84, "High"),
        ("Prototype Source Code", "R&D", 85, 12, 60, "Medium"),
        ("Contracts Repository", "Legal", 78, 15, 50, "Medium"),
        ("Litigation Strategy", "Legal", 86, 10, 66, "High"),
        ("Supply Chain Telemetry", "Operations", 55, 3, 22, "Low"),
        ("Facility Access Logs", "Operations", 48, 2, 15, "Low"),
        ("Vendor Credentials", "Operations", 82, 5, 58, "Medium"),
    ],
    columns=["Asset", "Department", "Sensitivity", "Shelf Life (yrs)", "Exposure Risk", "Risk Level"],
)

servers = pd.DataFrame(
    [
        # department, RSA-2048, ECC (P-256), ML-KEM-512, ML-KEM-768, downgrade-capable servers
        ("Finance", 34, 22, 18, 46, 19),
        ("HR", 28, 15, 12, 20, 11),
        ("R&D", 22, 18, 25, 55, 14),
        ("Legal", 18, 10, 8, 14, 7),
        ("Operations", 40, 30, 20, 25, 24),
    ],
    columns=["Department", "RSA-2048", "ECC (P-256)", "ML-KEM-512", "ML-KEM-768", "Downgrade-Capable"],
)
ALGOS = ["RSA-2048", "ECC (P-256)", "ML-KEM-512", "ML-KEM-768"]
LEGACY = ALGOS[:2]
ALGO_COLORS = {"RSA-2048": "#d13438", "ECC (P-256)": "#e8742a", "ML-KEM-512": "#5aa6d6", "ML-KEM-768": "#1f6fb2"}

# ----------------------------- Sidebar --------------------------------------
st.sidebar.header("🔎 Filters")
dept_sel = st.sidebar.multiselect("Department", DEPARTMENTS, default=DEPARTMENTS)
risk_sel = st.sidebar.multiselect("Risk level", RISK_LEVELS, default=RISK_LEVELS)
st.sidebar.caption("Synthetic data for demonstration only.")

f_assets = assets[assets["Department"].isin(dept_sel) & assets["Risk Level"].isin(risk_sel)]
f_servers = servers[servers["Department"].isin(dept_sel)]

# ----------------------------- Metrics --------------------------------------
tot = f_servers[ALGOS].sum().sum()
pq = f_servers[["ML-KEM-512", "ML-KEM-768"]].sum().sum()
migrated = (pq / tot * 100) if tot else 0.0
legacy = tot - pq
downgrade = int(f_servers["Downgrade-Capable"].sum())
crit = int((f_assets["Risk Level"] == "Critical").sum())

if migrated < 50 or crit >= 3:
    status, banner = "Critical", st.error
elif migrated < 75 or crit > 0 or downgrade > 0:
    status, banner = "Warning", st.warning
else:
    status, banner = "Healthy", st.success

# ----------------------------- Header ---------------------------------------
st.title("🔐 Post-Quantum Cryptography Security Monitor")
st.caption("Organizational migration to ML-KEM (FIPS 203)")

if f_servers.empty:
    st.info("No data for the selected departments. Adjust the sidebar filters.")
    st.stop()

banner(
    f"**Overall status: {status}** — {migrated:.0f}% of endpoints use ML-KEM; "
    f"{crit} critical HNDL asset(s); {downgrade} server(s) can be downgraded to legacy crypto."
)

c1, c2 = st.columns([1.2, 2])
with c1:
    gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=migrated,
            number={"suffix": "%"},
            title={"text": "PQC Migration Progress"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#1f6fb2"},
                "steps": [
                    {"range": [0, 50], "color": "#f6d0d1"},
                    {"range": [50, 75], "color": "#fbe9c2"},
                    {"range": [75, 100], "color": "#cdeedd"},
                ],
                "threshold": {"line": {"color": "#222", "width": 3}, "value": 90},
            },
        )
    )
    gauge.update_layout(height=280, margin=dict(l=20, r=20, t=60, b=10))
    st.plotly_chart(gauge, use_container_width=True)
with c2:
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Endpoints tracked", f"{int(tot)}")
    k2.metric("Post-quantum", f"{int(pq)}")
    k3.metric("Legacy (RSA/ECC)", f"{int(legacy)}")
    k4.metric("Downgrade-capable", downgrade)
    st.progress(min(int(migrated), 100), text="Target: 90% migrated")

st.divider()

# ----------------------------- HNDL risk ------------------------------------
st.subheader("🕰️ Harvest-Now-Decrypt-Later (HNDL) Risk")
if f_assets.empty:
    st.info("No assets match the selected filters.")
else:
    d = f_assets.sort_values("Exposure Risk")
    fig = px.bar(
        d, x="Exposure Risk", y="Asset", orientation="h", color="Risk Level",
        color_discrete_map=RISK_COLORS, category_orders={"Risk Level": RISK_LEVELS},
        hover_data={"Sensitivity": True, "Shelf Life (yrs)": True, "Department": True},
        text="Sensitivity",
    )
    fig.update_traces(texttemplate="Sensitivity %{text}", textposition="inside")
    fig.update_layout(
        height=max(320, 36 * len(d) + 120), xaxis_range=[0, 100],
        xaxis_title="Estimated exposure risk (0–100)", yaxis_title=None,
        margin=dict(l=10, r=10, t=10, b=10), legend_title="Risk level",
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption("Exposure grows with data sensitivity and shelf life: long-lived data captured today may be decrypted by a future quantum computer.")

st.divider()

# ----------------------------- Downgrade / protocol usage -------------------
st.subheader("⬇️ Downgrade Risk & Protocol Usage")
long = f_servers.melt(id_vars="Department", value_vars=ALGOS, var_name="Algorithm", value_name="Servers")
fig2 = px.bar(
    long, x="Department", y="Servers", color="Algorithm", barmode="stack",
    color_discrete_map=ALGO_COLORS, category_orders={"Algorithm": ALGOS},
)
fig2.update_layout(height=380, margin=dict(l=10, r=10, t=10, b=10), yaxis_title="Active servers")
st.plotly_chart(fig2, use_container_width=True)

# Table is rendered full width, below the chart, so all columns fit without horizontal scrolling.
t = f_servers.copy()
t["Legacy"] = t[LEGACY].sum(axis=1)
t["Post-Quantum"] = t[["ML-KEM-512", "ML-KEM-768"]].sum(axis=1)
t["Downgrade Exposure %"] = (t["Downgrade-Capable"] / (t["Legacy"] + t["Post-Quantum"]) * 100).round(1)
t["Risk"] = pd.cut(t["Downgrade Exposure %"], [-1, 15, 25, 1000], labels=["Low", "Medium", "High"]).astype(str)
st.dataframe(
    t[["Department", "Legacy", "Post-Quantum", "Downgrade-Capable", "Downgrade Exposure %", "Risk"]]
    .style.background_gradient(subset=["Downgrade Exposure %"], cmap="OrRd")
    .format({"Downgrade Exposure %": "{:.1f}"}),
    use_container_width=True, hide_index=True,
    height=35 * (len(t) + 1) + 3,
)
st.caption("Downgrade-capable servers still accept RSA/ECC fallback, letting an attacker force a non-PQ handshake.")
