# Vulnerability Trend Collector

A Python-based collector that ingests vulnerability data through a vendor-agnostic adapter layer (**Tenable.io** today via the Exports API; the adapter interface in `vendors/` is designed so a future CrowdStrike Falcon Exposure Management or Intune source can plug in without touching the rest of the pipeline), normalizes it into one findings table, enriches it with **CISA Known Exploited Vulnerabilities (KEV)** data, classifies by **site**, **severity**, **product**, and **remote exploitability**, and stores daily metrics in PostgreSQL for long-term trending and BI dashboards (Power BI).

Designed to replace manual CSV exports, pivot-table hell, and one-off reporting.

---

## 1. Features

- **Vendor-agnostic ingest** (`ingest_findings.py`): each source implements one adapter interface (`vendors/base.py`) and yields normalized findings into `vuln_findings` — the rest of the pipeline (rollups, KEV enrichment, Power BI) doesn't care which vendor a finding came from.
- **One export per run, not three.** Site/SLA/product classification used to independently re-pull the same Tenable export three separate times; now it's pulled once and everything else derives from the stored result via SQL.
- **Site-aware reporting** using Tenable tags (e.g., Site A, Site B etc.), with untagged assets grouped into `Ungrouped`.
- **Severity breakdown**: Critical / High / Medium / Low.
- **Remote/no-auth exploitability detection** using CVSS vectors (v2, v3, and v4).
- **SLA metrics** per site and risk band (total vs breaches, including remote), plus a proper **MTTR tracker** (`daily_mttr_metrics`) showing mean/median time-to-remediate and SLA compliance rate of what actually got fixed, broken down by severity.
- **CISA KEV enrichment** (`kev_sync.py`): flags open findings whose CVE is in the CISA Known Exploited Vulnerabilities catalog, including ransomware-use and past-due-remediation flags.
- **"Worst devices" hit list** (`asset_risk_summary` view): every asset ranked by a weighted risk score across open severity counts, KEV exposure, and remote/no-auth findings.
- **PostgreSQL-backed snapshots** with daily snapshots for easy trend charts and KPIs.

---

## 2. Prerequisites

### 2.1 Linux Host

Tested on Fedora Server. Other modern distros (Ubuntu/Mint) should work with equivalent package names.

Install base packages:

```bash
sudo dnf install -y python3 python3-venv python3-pip git
```

Clone the project:

```bash
git clone https://<your-repo-or-location>/tenable-tracker
cd tenable-tracker
```

Create and activate a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python dependencies:

```bash
pip install requests pyyaml psycopg2-binary
```

---

## 3. Tenable.io Requirements

You will need:

- Tenable.io **Access Key**
- Tenable.io **Secret Key**
- A user/role with permission to:
  - Use the Exports API
  - Read **vulnerabilities**
  - Read **assets** (including tags)

These values go into `secrets.yaml` (see Section 4).

---

## 4. Configuration

### 4.1 Secrets (`secrets.yaml`)

Copy the example file and fill in your values:

```bash
cp secrets.yaml.example secrets.yaml
```

`secrets.yaml` is listed in `.gitignore` and should never be committed.

```yaml
tenable:
  access_key: "YOUR_TENABLE_ACCESS_KEY"
  secret_key: "YOUR_TENABLE_SECRET_KEY"

database:
  user: "tenable_trends_user"
  password: "ChangeMe123!"
```

### 4.2 Main config (`config.yaml`)

The collector uses `config.yaml` for everything non-secret:

- Tenable API base URL
- Filters (last seen, published age, exploitability behaviour)
- Site mapping (tag value → human label)
- Tag categories (for sites / asset types)
- Database connection settings (credentials come from `secrets.yaml`)

```yaml
tenable:
  base_url: "https://cloud.tenable.com"

# Enabled vulnerability data sources. Each "type" must have a matching
# adapter in vendors/ (see vendors/__init__.py's ADAPTERS registry).
# Today only "tenable" exists; a future CrowdStrike Falcon Exposure
# Management or Intune adapter would add another entry here.
sources:
  - name: tenable
    type: tenable
    enabled: true

reporting:
  days_last_seen: 30
  vuln_published_older_than_days: 30
  # true  = only flag remote/no-auth vulns that also have a known exploit (recommended)
  # false = flag all network-accessible, no-auth vulns regardless of exploit availability
  require_exploit_for_remote_no_auth: true
  retention_days: 540
  # How long FIXED-state rows live in vuln_findings before maintenance.sh
  # prunes them. Separate from retention_days (which governs the daily_*
  # aggregate snapshot tables).
  findings_retention_days: 180

sites:
  - key: "BDH-Site"
    label: "BDH"
  - key: "BH-Site"
    label: "BH"
  # Add your own site tag keys and labels here

ungrouped_label: "Ungrouped"

tags:
  site_category: "Sites"
  asset_type_category: "AssetType"
  internet_values: ["InternetFacing"]
  server_values: ["Server"]
  workstation_values: ["Workstation"]

database:
  engine: "postgres"
  host: "127.0.0.1"
  port: 5432
  name: "tenable_trends"

secrets_file: "secrets.yaml"
```

---

## 5. Tenable Filters / Logic

`ingest_findings.py` pulls every OPEN/REOPENED/FIXED finding (all severities) into `vuln_findings` — it does not apply the `days_last_seen` staleness bound at fetch time, so nothing is discarded on ingest. That bound is instead applied uniformly, every time, by `rollup_daily_metrics.py` when it computes `daily_site_metrics` / `daily_sla_metrics` / `daily_product_metrics` / `daily_kev_metrics`: an OPEN/REOPENED finding only counts toward those snapshots if it was last seen within `days_last_seen`. The reasoning: an asset that hasn't checked in within that window has usually gone dark for an unrelated reason (decommissioned, offline), not because the finding stopped being real — so trend/SLA reporting excludes it, but the raw record stays in `vuln_findings` for investigation.

Remote/no-auth classification uses CVSS vectors (v2, v3, and v4 all supported):

- Attack Vector: Network or Adjacent
- Privileges Required: None
- (Optional) Known exploit required — controlled by `require_exploit_for_remote_no_auth`

---

## 6. Classification & Metrics

### Severity

Severity is determined first from CVSS base score, with Tenable's own severity as fallback:

| Score     | Band     |
|-----------|----------|
| ≥ 9.0     | Critical |
| 7.0–8.9   | High     |
| 4.0–6.9   | Medium   |
| < 4.0     | Low      |

### SLA Thresholds

| Band     | SLA (days) |
|----------|------------|
| Critical | 2          |
| High     | 14         |
| Medium   | 30         |
| Low      | 60         |

SLA age is measured from `first_found`. A finding is a breach if its age exceeds the band threshold.

---

## 7. Database Schema

### `daily_site_metrics`

Daily severity counts per site.

| Column        | Type    |
|---------------|---------|
| snapshot_date | TEXT    |
| site_label    | TEXT    |
| site_tag      | TEXT    |
| crit          | INTEGER |
| high          | INTEGER |
| medium        | INTEGER |
| low           | INTEGER |
| total         | INTEGER |
| remote_crit   | INTEGER |
| remote_high   | INTEGER |
| assets        | INTEGER |

### `daily_sla_metrics`

SLA tracking per site and risk band.

| Column                 | Type    |
|------------------------|---------|
| snapshot_date          | TEXT    |
| site_label             | TEXT    |
| site_tag               | TEXT    |
| risk                   | TEXT    |
| total_vulns            | INTEGER |
| sla_breaches           | INTEGER |
| remote_no_auth_vulns   | INTEGER |
| remote_no_auth_breaches| INTEGER |

### `vuln_findings`

The normalized, vendor-agnostic core table. One row per (source, source_asset_id, source_rule_id, port, protocol) — every OPEN/REOPENED/FIXED finding a source adapter reports, unfiltered by staleness. Everything else (daily snapshots, KEV enrichment, Power BI views) derives from this table. Key columns: `source`, `state`, `severity`, `cvss_score`/`cvss_vector`, `is_remote_no_auth`, `product_key`/`product_vendor`/`product_family`, `site_label`/`site_tag`/`asset_type`/`hostname`, `first_found`/`last_found`/`last_fixed`.

### `vuln_finding_cves`

CVEs per finding (`finding_id`, `cve`), many-to-many since a finding can map to multiple CVEs.

### `cisa_kev`

CISA Known Exploited Vulnerabilities catalog, synced daily by `kev_sync.py` from the public feed. Keyed by `cve_id`; includes `date_added`, `due_date`, `known_ransomware_campaign_use`.

### `daily_kev_metrics`

Daily KEV exposure per site: open KEV count (by severity), ransomware-flagged count, past-due-date count, non-KEV open count.

### `daily_mttr_metrics`

Daily remediation-time trend, per site and severity, for findings that closed **that day** (not a rolling window): `fixed_count`, `avg_remediation_days`, `median_remediation_days`, `sla_compliant_count`, `sla_compliance_rate`.

### Power BI views

- **`fact_vuln_findings_current`** — every currently open/reopened finding, with `age_days`, `sla_breach`, `has_kev`, `kev_due_date`, `kev_ransomware_use` computed. This is the main fact view for drill-down tables.
- **`asset_risk_summary`** — one row per asset (the "worst devices" hit list), with open severity counts, KEV/remote-no-auth counts, oldest open finding age, and a weighted `risk_score` for ranking.
- **`dim_site`**, **`dim_product`** — small lookup dimensions.

Tables are created automatically on first run (`db_schema.py`, called from `ingest_findings.py` / `rollup_daily_metrics.py` / `kev_sync.py`).

---

## 8. PostgreSQL Setup

```bash
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

Create DB and user:

```sql
sudo -u postgres psql
CREATE DATABASE tenable_trends;
CREATE USER tenable_trends_user WITH ENCRYPTED PASSWORD 'ChangeMe123!';
GRANT ALL PRIVILEGES ON DATABASE tenable_trends TO tenable_trends_user;
\q
```

Update the `database` section of `config.yaml` and `secrets.yaml` accordingly.

---

## 9. Running the Collector

```bash
cd /root/tenable-tracker
source venv/bin/activate
python3 ingest_findings.py --config config.yaml
python3 rollup_daily_metrics.py --config config.yaml
```

Or just run the full pipeline via `run_collector.sh` (see Section 10).

**Expected runtime:** On a large Tenable tenant (50k+ assets, 500k+ findings), a full run typically takes 10–30 minutes. The majority of that time is waiting for the Tenable export job to complete on their end — the polling loop inside `ingest_findings.py` is normal. This is now **one** Tenable export per run (it used to be three separate exports across three scripts for overlapping data), so total wall time should be noticeably shorter than before.

### Validating before you trust it

`rollup_daily_metrics.py --dry-run` prints the computed rollup for today without writing anything — useful for comparing against known-good numbers before relying on the new pipeline, or for spot-checking after a `product_groups.yaml` rule change.

### First run on a new box

`bootstrap.sh` runs the one-time sequence to populate the new schema from scratch and confirm it's ready for the Grafana dashboard: `ingest_findings.py` → `rollup_daily_metrics.py --dry-run` (preview) → `rollup_daily_metrics.py` (write) → `kev_sync.py` → `grafana/preflight_check.py`. This is separate from `run_collector.sh` (the nightly cron pipeline, which also handles asset collection and product reclassification) — run it once after deploying to a new box, or any time you want to re-verify the pipeline end to end.

```bash
./bootstrap.sh
```

---

## 10. Cron Automation

```bash
0 2 * * * cd /root/tenable-tracker && /root/tenable-tracker/venv/bin/python3 run_collector.sh >> /root/tenable-tracker/logs/collector.log 2>&1
```

---

## 11. Power BI Integration

1. Open Power BI Desktop
2. Get Data → PostgreSQL database
3. Server: your VM IP
4. Database: `tenable_trends`
5. Import mode (not DirectQuery) — matches the nightly refresh cadence.

### Existing report

The current report (`Vuln-Analysis-Current.pbix`) has two pages, both reading raw columns directly (no DAX measures defined yet):

- **Vuln Management** — KPIs for Remote Critical / Remote High / Total Assets, a stacked area chart of Critical/High/Medium/Low over time (`daily_site_metrics`), a site pivot table, and a product-family pivot table (`daily_product_metrics`), with a site slicer.
- **Assets** — a small table comparing asset counts across `asset_inventory.cs_assets_raw` and `asset_inventory.tn_assets_raw`.

These keep working unchanged — nothing in this pipeline renamed or restructured `daily_site_metrics`, `daily_product_metrics`, `tn_assets_raw`, or `cs_assets_raw`.

### Recommended additions

Add these as new pages/visuals against the new tables/views, and start defining real DAX measures instead of dragging raw columns:

- **KEV Exposure** — KPI tiles (Open KEV Count, Ransomware-Flagged Count, Past-Due Count) and a trend line from `daily_kev_metrics`; a table of currently open KEV findings from `fact_vuln_findings_current` filtered to `has_kev = TRUE`, sorted by `kev_due_date` ascending.
- **Worst Devices** — a table against `asset_risk_summary`, sorted by `risk_score` descending (Top N filter for a real "hit list"), with drill-through into `fact_vuln_findings_current` filtered by `source_asset_id`.
- **MTTR & SLA Tracking** — a trend line of `avg_remediation_days`/`median_remediation_days` from `daily_mttr_metrics`, split by severity, plus `sla_compliance_rate` as a KPI per risk band — this is the direct "are we tracking to our SLAs" view.

Suggested DAX measures (names + plain-language definitions — write these once against `fact_vuln_findings_current` instead of re-dragging raw columns onto every visual):

| Measure | Definition |
|---|---|
| Open Findings | `COUNTROWS(fact_vuln_findings_current)` |
| SLA Breach Rate | Count where `sla_breach = TRUE` ÷ Open Findings |
| % Findings with Active KEV | Count where `has_kev = TRUE` ÷ Open Findings |
| Open KEV Count | Count where `has_kev = TRUE` |
| KEV Past Due | Count where `has_kev = TRUE AND kev_due_date < TODAY()` |
| Remote/No-Auth Critical Share | Count where `severity = "critical" AND is_remote_no_auth = TRUE` ÷ Open Findings |
| Ransomware-Associated Open Count | Count where `kev_ransomware_use = "Known"` |

---

## 11a. Grafana (companion dashboard)

`grafana/vuln-dashboard.json` is a dashboard-as-code alternative/companion to the `.pbix` — same underlying views, kept in this repo so it evolves with the schema instead of needing manual rebuilding. It does not replace `Vuln-Analysis-Current.pbix`; both can point at the same database.

Pages (as Grafana rows): Executive Summary, SLA Compliance, CISA KEV Exposure, Worst Devices (the `asset_risk_summary` hit list), MTTR & SLA Tracking, Product/Vendor Drilldown. A `$site` template variable (multi-select, sourced from `dim_site`) filters every panel.

### Installing Grafana (if it isn't already on the box)

```bash
sudo tee /etc/yum.repos.d/grafana.repo <<EOF
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF

sudo dnf install -y grafana
sudo systemctl enable --now grafana-server
```

Grafana OSS is a core package — the PostgreSQL datasource type ships built in, no extra plugin install needed. Default UI: `http://<host>:3000`, default login `admin`/`admin` (forced change on first login).

### Preflight check

```bash
python3 grafana/preflight_check.py --config config.yaml
```

Checks Postgres connectivity, confirms every table/view the dashboard queries exists and has data (not just that `ingest_findings.py` ran once, but that `rollup_daily_metrics.py` and `kev_sync.py` have too), and flags configured sites with no findings yet -- these are hard requirements and it exits non-zero if any are missing.

It also checks Grafana itself, informationally (never blocks the exit code, since the data pipeline doesn't depend on Grafana being up): whether a local `grafana-server` systemd service is active, and whether `/api/health` responds -- using `grafana.url` from `config.yaml` if you've set one, otherwise guessing `http://127.0.0.1:3000` and saying so explicitly. On a box where Grafana genuinely isn't installed yet, expect `[INFO]` lines here, not `[FAIL]` -- that's the check correctly telling you what's missing, not something broken.

**To go live:**

1. `python3 grafana/preflight_check.py --config config.yaml` — fix anything it flags as `[FAIL]`. If Grafana shows as not reachable, install it (above) and re-run.
2. In Grafana: Connections → Data sources → add a PostgreSQL datasource pointing at the same database as `config.yaml`.
3. Dashboards → Import → upload `grafana/vuln-dashboard.json` → when prompted for the `DS_POSTGRESQL` input, select the datasource from step 2.
4. This hasn't been round-tripped through a live Grafana instance during development (no Grafana available to test against) — the SQL and schema are verified, but expect to nudge panel positions/formatting on first import.

---

## 12. Maintenance

`maintenance.sh` handles DB pruning (`daily_site_metrics`, `daily_sla_metrics`, `daily_kev_metrics`, `daily_product_metrics`, and FIXED-state rows in `vuln_findings` past `findings_retention_days`), product reclassification, VACUUM, and log rotation. Run it weekly via cron:

```bash
0 3 * * 0 /root/tenable-tracker/maintenance.sh >> /root/tenable-tracker/logs/maintenance.log 2>&1
```

**Note:** `maintenance.sh` calls `psql` directly and requires password-free database access. Set this up via one of:

- A `~/.pgpass` entry: `127.0.0.1:5432:tenable_trends:tenable_trends_user:yourpassword`
- `PGPASSWORD` set in the cron environment
- `pg_hba.conf` set to `trust` for localhost (not recommended for production)

---

## 13. Hit-By-A-Bus Notes

- `config.yaml` contains all mapping rules and filter settings
- `secrets.yaml` holds all credentials (never committed)
- Tables are created automatically on first run (`db_schema.py`)
- Cron automates daily ingestion via `run_collector.sh`: `ingest_findings.py` → `rollup_daily_metrics.py` → `reclassify_product_families.py` → `kev_sync.py` → asset inventory (`crowdstrike_pull_assets.py`, `tenable_pull_assets.py`, `asset_match_hostname.py`)
- `config.py`/`db.py`/`cvss.py`/`sites.py`/`product_classify.py` are shared modules every other script imports from — edit logic there once, not per-script
- Adding a new vendor: implement `fetch_findings(cfg)` in `vendors/<name>.py` per the contract in `vendors/base.py`, register it in `vendors/ADAPTERS`, add a `sources:` entry in `config.yaml`
- Power BI reads directly from the PostgreSQL database — see Section 11 for the current report's pages and recommended additions
- Dependencies: Python 3, `requests`, `pyyaml`, `psycopg2-binary`, PostgreSQL
