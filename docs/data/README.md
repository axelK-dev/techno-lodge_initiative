# Data & Rollout Sites

This folder documents inputs like `rollout_sites.csv` and any governance logs.

## `rollout_sites.csv` (proposed columns)
- `site_id` — unique identifier
- `name` — lodge/site name
- `region` — city/county/tribal land
- `phase` — tribal‑first / rural / urban
- `connectivity` — target speed (e.g., 150/150 Mbps)
- `modules` — cultural | education | community (pipe‑separated)
- `go_live_date` — planned launch
- `status` — planned | building | live

## Data Governance
- Store only operational data necessary for rollout tracking.
- If minors participate, separate any education records under FERPA scope.

## Using the Data in Dashboards
- Load `rollout_sites.csv` to map sites and compute KPIs.
- Publish a quarterly snapshot for transparency.
