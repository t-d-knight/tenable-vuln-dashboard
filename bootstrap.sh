#!/bin/bash
set -euo pipefail

# bootstrap.sh
# One-time (or as-needed) sequence to populate the vendor-agnostic schema
# from scratch -- vuln_findings, cisa_kev, epss_scores, daily_kev_metrics,
# daily_epss_metrics, daily_mttr_metrics, and the Power BI/Grafana views --
# then verifies the result is ready for the Grafana dashboard import.
#
# This is NOT the nightly cron pipeline -- see run_collector.sh for that.
# Run this once after deploying this code to a box, or any time you want
# to re-verify the pipeline end-to-end before trusting cron with it.
#
# Usage: ./bootstrap.sh

cd "$(dirname "$0")"
source venv/bin/activate

echo "=== [1/7] Syncing CISA KEV catalog ==="
python3 kev_sync.py --config config.yaml

echo
echo "=== [2/7] Syncing EPSS scores ==="
python3 epss_sync.py --config config.yaml

echo
echo "=== [3/7] Ingesting findings (triggers a Tenable export -- may take a while) ==="
python3 ingest_findings.py --config config.yaml

echo
echo "=== [4/7] Backfilling CVSS vectors from NVD (rate-limited, capped per run) ==="
python3 nvd_enrich.py --config config.yaml

echo
echo "=== [5/7] Rollup dry-run (preview only, nothing written yet) ==="
python3 rollup_daily_metrics.py --config config.yaml --dry-run

echo
echo "=== [6/7] Rollup (writing daily_site_metrics / daily_sla_metrics / daily_product_metrics / daily_kev_metrics / daily_epss_metrics / daily_mttr_metrics) ==="
python3 rollup_daily_metrics.py --config config.yaml

echo
echo "=== [7/7] Preflight check ==="
python3 ./grafana/preflight_check.py --config config.yaml

echo
echo "Bootstrap complete. If preflight reported all PASS, proceed to the Grafana"
echo "datasource + dashboard import steps in the README (Section 11a)."
