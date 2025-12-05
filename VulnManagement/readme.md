# Tenable Vulnerability Trend Collector

A Python-based collector that pulls filtered vulnerability data from **Tenable Vulnerability Management (Tenable.io)** via the **Exports API**, enriches it with **asset tags**, classifies by **site**, **severity**, and **remote exploitability**, and stores daily metrics in a database for long-term trending and BI dashboards (Power BI / Grafana).

Designed to replace manual CSV exports, pivot-table hell, and one-off reporting.

---

## 1. Features

- **Automated daily ingestion** of Tenable.io vulnerability data via the Exports API.
- **Site-aware reporting** using Tenable tags (e.g., BDH, BH, MTHCS, etc.), with untagged assets grouped into `Ungrouped`.
- **Severity breakdown**: Critical / High / Medium / Low.
- **Remote/no-auth exploitability detection** using CVSS vectors (network, low complexity, no privileges).
- **SLA metrics** per site and risk band (total vs breaches, including remote).
- **Database-backed snapshots**:
  - SQLite (simple/testing)
  - PostgreSQL (recommended for production + Power BI).
- **BI-friendly schema**: daily snapshots for easy trend charts and KPIs.

---

## 2. Prerequisites

### 2.1 Linux Host

Tested on Fedora Server. Other modern distros (Ubuntu/Mint) should work with equivalent package names.

Install base packages:
```
sudo dnf install -y python3 python3-venv python3-pip git
```
Clone the project:
```
git clone https://<your-repo-or-location>/tenable-tracker
cd tenable-tracker
```
Create and activate a Python virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```
Install Python dependencies:
```
pip install requests pyyaml
```
If using PostgreSQL (recommended):
```
pip install psycopg2-binary
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

These values go into `config.yaml`.

---

## 4. Configuration (`config.yaml`)

The collector uses a YAML configuration file for:

- Tenable API credentials
- Filters (last seen, published age, exploitability behaviour)
- Site mapping (tag value → human label)
- Tag categories (for sites / asset types)
- Database connection settings

### 4.1 Example config (current working setup)
```
tenable:
  access_key: "YOUR_TENABLE_ACCESS_KEY"
  secret_key: "YOUR_TENABLE_SECRET_KEY"

reporting:
  days_last_seen: 30
  vuln_published_older_than_days: 30
  require_exploit_for_remote_no_auth: true
  retention_days: 540

sites:
  - key: "BDH-Site"
    label: "BDH"
  - key: "BH-Site"
    label: "BH"
  - key: "HH-Site"
    label: "HH"
  - key: "DH-Site"
    label: "DH"
  - key: "CDH-Site"
    label: "CDH"
  - key: "ERH-Site"
    label: "ERH"
  - key: "MDHS-Site"
    label: "MDHS"
  - key: "IDHS-Site"
    label: "IDHS"
  - key: "MBPH-Site"
    label: "MBPH"
  - key: "KDH-Site"
    label: "KDH"
  - key: "SHDH-Site"
    label: "SHDH"
  - key: "REDHS-Site"
    label: "REDHS"
  - key: "RDHS-Site"
    label: "RDHS"
  - key: "MTHCS-Site"
    label: "MTHCS"
  - key: "LMHA-Site"
    label: "LMHA"

ungrouped_label: "Ungrouped"

tags:
  site_category: "Sites"
  asset_type_category: "AssetType"
  internet_values: ["InternetFacing"]
  server_values: ["Server"]
  workstation_values: ["Workstation"]

database:
  engine: "sqlite"
  db_path: "tenable_trends.sqlite"
```
---

## 5. Tenable Filters / Logic

Matches your UI filter:

Active, Resurfaced, New → Severity High/Critical → Last Seen ≤ X days → Published > X days

Exports API filters:

- state: ["OPEN", "REOPENED"]
- severity: ["high", "critical"]
- last_found: <epoch>

plugin_published logic optional.

---

## 6. Classification & Metrics

### Severity

- critical
- high
- medium
- low

### Remote / No-Auth Logic

- Attack Vector: Network
- Complexity: Low
- Privileges: None
- (Optional) exploit required

### SLA Metrics

Tracked per site:

- total
- breaches
- remote_total
- remote_breaches

---

## 7. Database Schema

### daily_site_metrics

- snapshot_date
- site_label
- crit
- high
- medium
- low
- remote_crit
- remote_high
- assets
- total

### daily_sla_metrics

- snapshot_date
- site_label
- risk
- total
- breaches
- remote_total
- remote_breaches

---

## 8. Running the Collector
```
cd /root/tenable-tracker
source venv/bin/activate
python3 tenable_trend_collector.py
```
---

## 9. Cron Automation
```
0 2 * * * cd /root/tenable-tracker && /root/tenable-tracker/venv/bin/python3 tenable_trend_collector.py >> /root/tenable-tracker/collector.log 2>&1
```
---

## 10. PostgreSQL Setup
```
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```
# Create DB + User
```
sudo -u postgres psql
CREATE DATABASE tenable_trends;
CREATE USER tenable_trends_user WITH ENCRYPTED PASSWORD 'ChangeMe123!';
GRANT ALL PRIVILEGES ON DATABASE tenable_trends TO tenable_trends_user;
\q
```
Update config:
```
database:
  engine: "postgres"
  host: "127.0.0.1"
  port: 5432
  name: "tenable_trends"
  user: "tenable_trends_user"
  password: "ChangeMe123!"
```
---

## 11. Power BI Integration

1. Open Power BI Desktop
2. Get Data → PostgreSQL database
3. Server: your VM IP
4. Database: tenable_trends
5. Select daily_site_metrics + daily_sla_metrics

---

## 12. Hit-By-A-Bus Notes

- config.yaml contains all keys and mapping rules
- Script auto-creates DB tables
- Cron automates daily ingestion
- Power BI reads directly from DB
- Dependencies: Python, requests, YAML, PostgreSQL (optional)
