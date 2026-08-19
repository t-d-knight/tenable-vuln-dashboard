#!/bin/bash
set -euo pipefail

# bootstrap.sh
# One-time (or as-needed) sequence to populate the vendor-agnostic schema
# from scratch -- vuln_findings, cisa_kev, daily_kev_metrics,
# daily_mttr_metrics, and the Power BI/Grafana views -- then verifies the
# result is ready for the Grafana dashboard import.
#
# This is NOT the nightly cron pipeline -- see run_collector.sh for that.
# Run this once after deploying this code to a box, or any time you want
# to re-verify the pipeline end-to-end before trusting cron with it.
#
# Usage: ./bootstrap.sh

cd "$(dirname "$0")"
source venv/bin/activate

echo "=== [1/5] Ingesting findings (triggers a Tenable export -- may take a while) ==="
python3 ingest_findings.py --config config.yaml

echo
echo "=== [2/5] Rollup dry-run (preview only, nothing written yet) ==="
python3 rollup_daily_metrics.py --config config.yaml --dry-run

echo
echo "=== [3/5] Rollup (writing daily_site_metrics / daily_sla_metrics / daily_product_metrics / daily_kev_metrics / daily_mttr_metrics) ==="
python3 rollup_daily_metrics.py --config config.yaml

echo
echo "=== [4/5] Syncing CISA KEV catalog ==="
python3 kev_sync.py --config config.yaml

echo
echo "=== [5/5] Preflight check ==="
python3 ./grafana/preflight_check.py --config config.yaml

echo
echo "Bootstrap complete. If preflight reported all PASS, proceed to the Grafana"
echo "datasource + dashboard import steps in the README (Section 11a)."
