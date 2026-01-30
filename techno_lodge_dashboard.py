# Techno-Lodge Dashboard (Washington) — stable minimal version
# ------------------------------------------------------------
# - Prefers real CSVs: data/real_sites.csv, data/real_kpis.csv, data/real_funding.csv
# - Robust CSV parsing, no caching, no seeding.
# - Clean header; interactivity kept simple; provenance at bottom on demand.

import os
from datetime import date
import pandas as pd
import streamlit as st
import plotly.express as px

# ---------- App ----------
st.set_page_config(page_title="Techno-Lodge Dashboard (WA)", layout="wide")
st.title("Techno-Lodge: Washington Overview")
st.caption("Explore sites, KPIs, and funding. Use filters to dig deeper. Provenance lives at the bottom.")

# ---------- Paths ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

REAL_SITES = os.path.join(DATA_DIR, "real_sites.csv")
REAL_KPIS  = os.path.join(DATA_DIR, "real_kpis.csv")
REAL_FUNDS = os.path.join(DATA_DIR, "real_funding.csv")

SEED_SITES = os.path.join(DATA_DIR, "rollout_sites.csv")
SEED_KPIS  = os.path.join(DATA_DIR, "metrics.csv")
SEED_FUNDS = os.path.join(DATA_DIR, "funding.csv")

PROVENANCE_MD = os.path.join(DATA_DIR, "provenance.md")

def pick_path(real_path, seed_path):
    if os.path.exists(real_path): return real_path
    if seed_path and os.path.exists(seed_path): return seed_path
    return None

def read_csv_safe(path):
    """CSV reader that tolerates commas/quotes inside text fields."""
    return pd.read_csv(
        path,
        engine="python",
        quotechar='"',
        escapechar='\\',
        sep=',',
        encoding="utf-8",
        on_bad_lines="error",
    )

# ---------- Load data ----------
sites_path = pick_path(REAL_SITES, SEED_SITES)
kpis_path  = pick_path(REAL_KPIS,  SEED_KPIS)
funds_path = pick_path(REAL_FUNDS, SEED_FUNDS)

if not all([sites_path, kpis_path, funds_path]):
    st.error("Missing one or more required CSVs (real_sites.csv, real_kpis.csv, real_funding.csv).")
    st.stop()

try:
    sites = read_csv_safe(sites_path)
    mets  = read_csv_safe(kpis_path)
    funds = read_csv_safe(funds_path)
except Exception as e:
    st.error(f"CSV parsing error: {e}")
    st.stop()

# ---------- Normalize ----------
# Strip whitespace in column names
sites.columns = [c.strip() for c in sites.columns]
mets.columns  = [c.strip() for c in mets.columns]
funds.columns = [c.strip() for c in funds.columns]

# Lat/Lon numeric
for col in ("lat","lon"):
    if col in sites.columns:
        sites[col] = pd.to_numeric(sites[col], errors="coerce")

# KPI numerics + provenance
for col in ("value","target"):
    if col in mets.columns:
        mets[col] = pd.to_numeric(mets[col], errors="coerce")
if "is_official" in mets.columns:
    mets["provenance"] = mets["is_official"].map(lambda x: "Official" if str(x).lower()=="true" else "Modeled")
else:
    mets["provenance"] = "Demo"

# Funding numeric + provenance
if "amount_usd" in funds.columns:
    funds["amount_usd"] = pd.to_numeric(funds["amount_usd"], errors="coerce")
if "citation_url" in funds.columns:
    funds["provenance"] = "Official"
else:
    funds["provenance"] = "Demo"

# ---------- Helpers ----------
def format_value(value, unit):
    if pd.isna(value): return "—"
    unit = (unit or "").strip()
    if unit == "": return f"{value}"
    if unit.lower().startswith("usd"):
        if "mill" in unit.lower(): return f"${value}M"       # USD (Millions)
        try: return f"${float(value):,.0f}"
        except: return f"${value}"
    return f"{value} {unit}"

# ---------- Filters (sidebar) ----------
with st.sidebar:
    st.header("Filters")
    phases = sorted(sites["phase"].dropna().unique().tolist()) if "phase" in sites.columns else []
    types  = sorted(sites["type"].dropna().unique().tolist()) if "type" in sites.columns else []
    sel_phase = st.multiselect("Phase", options=phases, default=phases)
    sel_type  = st.multiselect("Site type", options=types, default=types)
    module_q  = st.text_input("Module contains", "")

# ---------- Map ----------
st.subheader("Rollout Map (Washington)")
map_df = sites.copy()
if sel_phase: map_df = map_df[map_df["phase"].isin(sel_phase)]
if sel_type:  map_df = map_df[map_df["type"].isin(sel_type)]
if module_q and "modules" in map_df.columns:
    map_df = map_df[map_df["modules"].astype(str).str.contains(module_q, case=False, na=False)]

if {"lat","lon"}.issubset(map_df.columns) and not map_df.dropna(subset=["lat","lon"]).empty:
    fig = px.scatter_mapbox(
        map_df.dropna(subset=["lat","lon"]),
        lat="lat", lon="lon",
        hover_name="name" if "name" in map_df.columns else None,
        hover_data=[c for c in ["region","type","phase","modules","citation_url"] if c in map_df.columns],
        color="type" if "type" in map_df.columns else None,
        zoom=5, height=520
    )
    fig.update_layout(mapbox_style="open-street-map", margin=dict(l=0, r=0, t=0, b=0))
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No map points to display with current filters.")

# Optional sites table
if st.checkbox("Show sites table", value=False):
    st.dataframe(map_df, use_container_width=True)
    st.download_button("Download sites (filtered)", data=map_df.to_csv(index=False), file_name="sites_filtered.csv", mime="text/csv")

# ---------- KPIs ----------
st.subheader("Key KPIs")
kpi_df = mets.copy()
if "provenance" in kpi_df.columns:
    show_official = st.checkbox("Show official KPIs only", value=True)
    if show_official: kpi_df = kpi_df[kpi_df["provenance"]=="Official"]

cols = st.columns(2)
for i, row in kpi_df.iterrows():
    label = f"{row.get('metric','Metric')} ({row.get('provenance','Demo')})"
    value = row.get("value", None)
    target= row.get("target", None)
    unit  = row.get("unit","")
    if pd.isna(value) or pd.isna(target): continue
    pct   = (value / target) if (target and target != 0) else None
    val_d = format_value(value, unit)
    with cols[i % 2]:
        st.metric(label=label, value=val_d, delta=f"{pct*100:.1f}% of target" if pct else "—")

if st.checkbox("Show KPI table", value=False):
    st.dataframe(kpi_df, use_container_width=True)
    st.download_button("Download KPIs (filtered)", data=kpi_df.to_csv(index=False), file_name="kpis_filtered.csv", mime="text/csv")

# ---------- Funding ----------
st.subheader("Funding Overview")
fund_df = funds.copy()

# Simple toggles
include_national = st.checkbox("Include national rows (United States)", value=False)
if not include_national:
    fund_df = fund_df[fund_df.get("region","")!="United States"]

include_progsize = st.checkbox("Include 'Program Size' rows (e.g., TBCP total)", value=True)
if not include_progsize:
    fund_df = fund_df[fund_df.get("status","")!="Program Size"]

search = st.text_input("Search funding (source or program)", "")
if search:
    s = search.lower()
    fund_df = fund_df[
        fund_df.get("source","").str.lower().str.contains(s, na=False) |
        fund_df.get("program","").str.lower().str.contains(s, na=False)
    ]

# Render chart
if "amount_usd" in fund_df.columns and not fund_df.empty:
    fig = px.bar(
        fund_df,
        x="source",
        y="amount_usd",
        color="status" if "status" in fund_df.columns else None,
        text="status" if "status" in fund_df.columns else None,
        labels={"amount_usd":"Amount (USD)"},
        height=420
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, use_container_width=True)

    total = pd.to_numeric(fund_df["amount_usd"], errors="coerce").fillna(0).sum()
    st.metric("Total (sum of displayed rows)", f"${int(total):,}")
else:
    st.info("No funding rows to display with current filters.")

if st.checkbox("Show funding table", value=False):
    show_cols = [c for c in ["source","program","amount_usd","status","region","provenance","citation_url"] if c in fund_df.columns]
    st.dataframe(fund_df[show_cols], use_container_width=True)
    st.download_button("Download funding (filtered)", data=fund_df.to_csv(index=False), file_name="funding_filtered.csv", mime="text/csv")

# ---------- Timeline (optional visual cue) ----------
st.subheader("Rollout Timeline")
phases_data = [
    {"Task": "Phase 1 – Tribal-first pilots",   "Start": date(2025, 1, 1), "Finish": date(2025, 6, 30)},
    {"Task": "Phase 2 – Rural/Border expansion","Start": date(2025, 7, 1), "Finish": date(2026, 3, 31)},
    {"Task": "Phase 3 – Urban hubs",            "Start": date(2026, 4, 1), "Finish": date(2026, 12, 31)},
]
ph_df = pd.DataFrame(phases_data)
fig_t = px.timeline(ph_df, x_start="Start", x_end="Finish", y="Task", height=280)
fig_t.update_yaxes(autorange="reversed")
fig_t.update_layout(margin=dict(l=0, r=0, t=0, b=0))
st.plotly_chart(fig_t, use_container_width=True)

# ---------- Data & Provenance (bottom) ----------
with st.expander("Data & Provenance (click to open)"):
    st.markdown(f"- **Sites CSV**: `{sites_path}`")
    st.markdown(f"- **KPIs  CSV**: `{kpis_path}`")
    st.markdown(f"- **Funding CSV**: `{funds_path}`")
    if os.path.exists(PROVENANCE_MD):
        st.markdown("---")
        st.markdown("**provenance.md**")
        st.markdown(open(PROVENANCE_MD, "r", encoding="utf-8").read())
