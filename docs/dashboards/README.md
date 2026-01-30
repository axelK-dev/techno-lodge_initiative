# Dashboards & KPIs

Use the dashboard for **transparency**, **momentum**, and **funding leverage**.

## Core Views
- **Rollout Timeline** — Gantt by phase and region.
- **Interactive Map** — Lodge locations, modules (Cultural/Education/Community), connectivity status.
- **Metrics** — Access (speeds/devices), Adoption (course completions/credentials), Affordability (subsidies/devices), Cultural Integrity (tribal‑led programs), Inclusion (ADA audits, elders participation).

## Run Locally
```bash
python techno_lodge_dashboard.py
```

> The script can ingest `rollout_sites.csv` to map sites and compute KPIs.

## Open Data Endpoints (future)
- `/lodges` — name, location, phase, modules
- `/metrics` — equity KPIs
- `/broadband` — connectivity status by region
