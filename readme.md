# Tenable Vulnerability Trend Collector

A Python-based collector that pulls filtered vulnerability data from **Tenable Vulnerability Management (Tenable.io)** via the Exports API, enriches it with **asset tags**, classifies by **site**, **severity**, and **remote exploitability**, and stores daily metrics in PostgreSQL for long-term trending and BI dashboards (Power BI / Grafana).

Designed to replace manual CSV exports, pivot-table hell, and one-off reporting.

---

## 1. Features

- **Automated daily ingestion** of Tenable.io vulnerability data via the Exports API.
- **Site-aware reporting** using Tenable tags (e.g., BDH, BH, MTHCS, etc.), with untagged assets grouped into `Ungrouped`.
- **Severity breakdown**: Critical / High / Medium / Low.
- **Remote/no-auth exploitability detection** using CVSS vectors (network, low complexity, no privileges).
- **SLA metrics** per site and risk band (total vs breaches, including remote).
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

reporting:
  days_last_seen: 30
  vuln_published_older_than_days: 30
  # true  = only flag remote/no-auth vulns that also have a known exploit (recommended)
  # false = flag all network-accessible, no-auth vulns regardless of exploit availability
  require_exploit_for_remote_no_auth: true
  retention_days: 540

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

Targets active vulnerabilities matching:

- State: `OPEN` or `REOPENED`
- Severity: Critical / High / Medium / Low
- Last seen within `days_last_seen`

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

Tables are created automatically on first run.

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
python3 tenable_trend_collector.py
```

**Expected runtime:** On a large Tenable tenant (50k+ assets, 500k+ findings), a full run typically takes 10–30 minutes. The majority of that time is waiting for the Tenable export jobs to complete on their end — the polling loop is normal. `run_collector.sh` chains several scripts, each triggering its own Tenable export, so total wall time can be 30–60 minutes on large environments.

### Troubleshooting

Add `--debug` to dump raw plugin payloads and remote/no-auth classification examples to stdout:

```bash
python3 tenable_trend_collector.py --debug
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
5. Select `daily_site_metrics` and `daily_sla_metrics`

---

## 12. Maintenance

`maintenance.sh` handles DB pruning, product reclassification, VACUUM, and log rotation. Run it weekly via cron:

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
- Tables are created automatically on first run
- Cron automates daily ingestion via `run_collector.sh`
- Power BI reads directly from the PostgreSQL database
- Dependencies: Python 3, `requests`, `pyyaml`, `psycopg2-binary`, PostgreSQL
