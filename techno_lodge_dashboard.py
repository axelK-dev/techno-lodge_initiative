
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import date
import os

st.set_page_config(page_title="Techno-Lodge Dashboard", layout="wide")

DATA_DIR = "data"
SITES_CSV = os.path.join(DATA_DIR, "rollout_sites.csv")
METRICS_CSV = os.path.join(DATA_DIR, "metrics.csv")
FUNDING_CSV = os.path.join(DATA_DIR, "funding.csv")

def ensure_sample_data():
    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(SITES_CSV):
        sites = pd.DataFrame([
            {"site_id": 1, "name": "Yakima Techno-Lodge", "region": "Yakima County", "type": "Rural Hub",
             "phase": "Phase 1 – Tribal-first", "lat": 46.6021, "lon": -120.5059, "modules": "Cultural, Education"},
            {"site_id": 2, "name": "Tulalip Techno-Lodge", "region": "Tulalip Reservation", "type": "Tribal Land",
             "phase": "Phase 1 – Tribal-first", "lat": 48.0640, "lon": -122.2516, "modules": "Cultural, Community"},
            {"site_id": 3, "name": "Spokane Techno-Lodge", "region": "Spokane County", "type": "Urban Hub",
             "phase": "Phase 2 – Rural/Border", "lat": 47.6588, "lon": -117.4260, "modules": "Education, Community"},
            {"site_id": 4, "name": "Albany Pilot Corner", "region": "Linn County (OR)", "type": "Pilot",
             "phase": "Pilot – Demo", "lat": 44.6365, "lon": -123.1059, "modules": "Education"},
            {"site_id": 5, "name": "Colville Techno-Lodge", "region": "Colville Reservation", "type": "Tribal Land",
             "phase": "Phase 1 – Tribal-first", "lat": 48.5420, "lon": -118.5430, "modules": "Cultural, Education, Community"},
        ])
        sites.to_csv(SITES_CSV, index=False)

    if not os.path.exists(METRICS_CSV):
        metrics = pd.DataFrame([
            {"metric": "Access (Broadband ready sites)", "value": 3, "target": 10},
            {"metric": "Adoption (program completions)", "value": 120, "target": 500},
            {"metric": "Cultural integrity (tribal-led events)", "value": 18, "target": 80},
            {"metric": "Inclusion (ADA features deployed)", "value": 6, "target": 25},
        ])
        metrics.to_csv(METRICS_CSV, index=False)

    if not os.path.exists(FUNDING_CSV):
        funding = pd.DataFrame([
            {"source": "TBCP (Federal)", "amount": 10400000, "status": "Secured"},
            {"source": "BEAD (Federal)", "amount": 6500000, "status": "Pending"},
            {"source": "Digital Equity Act (State)", "amount": 15900000, "status": "Allocated"},
            {"source": "Private / Philanthropy", "amount": 1200000, "status": "In discussion"},
        ])
        funding.to_csv(FUNDING_CSV, index=False)

@st.cache_data
def load_data():
    ensure_sample_data()
    sites = pd.read_csv(SITES_CSV)
    mets = pd.read_csv(METRICS_CSV)
    funds = pd.read_csv(FUNDING_CSV)
    return sites, mets, funds

st.title("Techno-Lodge: Safety, Engagement & Scalability")
st.caption("Live prototype – Streamlit + Plotly + Pandas")

sites, mets, funds = load_data()

with st.sidebar:
    st.header("Filters")
    phase_sel = st.multiselect("Phase", options=sorted(sites['phase'].unique()), default=sorted(sites['phase'].unique()))
    type_sel = st.multiselect("Site type", options=sorted(sites['type'].unique()), default=sorted(sites['type'].unique()))
    module_search = st.text_input("Module contains", "")
    st.divider()
    st.subheader("About")
    st.write("If no CSVs are present, this app auto-creates sample data under ./data.")

filtered = sites[sites['phase'].isin(phase_sel) & sites['type'].isin(type_sel)]
if module_search:
    filtered = filtered[filtered['modules'].str.contains(module_search, case=False, na=False)]

col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("Rollout Map")
    fig = px.scatter_mapbox(
        filtered,
        lat='lat', lon='lon',
        hover_name='name', hover_data=['region', 'type', 'phase', 'modules'],
        color='type', zoom=5, height=520
    )
    fig.update_layout(mapbox_style='open-street-map', margin=dict(l=0, r=0, t=0, b=0))
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Key KPIs")
    kpi_cols = st.columns(2)
    for i, row in mets.iterrows():
        with kpi_cols[i % 2]:
            pct = row['value'] / max(row['target'], 1)
            st.metric(label=row['metric'], value=int(row['value']), delta=f"{pct*100:.1f}% of target")

st.divider()

st.subheader("Funding Overview")
fund_cols = st.columns([1.5, 1])
with fund_cols[0]:
    fund_bar = px.bar(funds, x='source', y='amount', color='status', text='status',
                      labels={'amount': 'Amount (USD)'}, height=380)
    fund_bar.update_traces(textposition='outside')
    st.plotly_chart(fund_bar, use_container_width=True)

with fund_cols[1]:
    total = int(funds['amount'].sum())
    st.metric("Total identified", f"${total:,.0f}")
    st.write(funds)

st.subheader("Rollout Timeline")
phases = [
    {"Task": "Phase 1 – Tribal-first pilots", "Start": date(2025, 1, 1), "Finish": date(2025, 6, 30)},
    {"Task": "Phase 2 – Rural/Border expansion", "Start": date(2025, 7, 1), "Finish": date(2026, 3, 31)},
    {"Task": "Phase 3 – Urban hubs", "Start": date(2026, 4, 1), "Finish": date(2026, 12, 31)},
]
phase_df = pd.DataFrame(phases)
fig_t = px.timeline(phase_df, x_start="Start", x_end="Finish", y="Task", height=260)
fig_t.update_yaxes(autorange="reversed")
fig_t.update_layout(margin=dict(l=0, r=0, t=0, b=0))
st.plotly_chart(fig_t, use_container_width=True)

st.subheader("Compliance check – demo")
st.caption("Simulates a COPPA/FERPA/CIPA/HIPAA-inspired checklist; no data is stored.")
with st.form("compliance_form"):
    age = st.number_input("User age", min_value=5, max_value=99, value=15)
    coppa = st.checkbox("COPPA: Parental consent for under 13")
    ferpa = st.checkbox("FERPA: Limit access to education records")
    cipa = st.checkbox("CIPA: Content filtering & safety policies")
    hipaa = st.checkbox("HIPAA-inspired: Encrypt telemetry & consent analytics")
    submitted = st.form_submit_button("Validate")
    if submitted:
        passed, failed = True, []
        if age < 13 and not coppa: failed.append("COPPA"); passed = False
        if not ferpa: failed.append("FERPA"); passed = False
        if not cipa: failed.append("CIPA"); passed = False
        if not hipaa: failed.append("HIPAA-inspired"); passed = False
        st.success("Compliance passed – proceed to onboarding ✨") if passed else st.error(f"Compliance failed: {', '.join(failed)}")

st.caption("You can later replace the CSVs or connect this to your FastAPI (`/health`, `/login`, `/onboard`).")