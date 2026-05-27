#!/bin/bash
set -euo pipefail

# run_collector.sh
# Daily collection pipeline. Intended to be run via cron:
#   0 2 * * * cd /root/tenable-tracker && ./run_collector.sh >> logs/collector.log 2>&1
#
# NOTE: Each script below triggers its own Tenable export job. On large tenants
# (50k+ assets, 500k+ findings) expect total wall time of 30–60 minutes. The
# poll loops are normal — Tenable export jobs are async on their end.

cd /root/tenable-tracker
source venv/bin/activate

# Regional trends snapshot (site × severity × SLA)
python3 tenable_trend_collector.py --config config.yaml

# Product-level metrics (Top 10, open/new/fixed by product)
python3 fill_daily_product_metrics.py --config config.yaml

# Reclassify product families to keep Top 10 clean after rule changes
python3 reclassify_product_families.py --config config.yaml

# Plugin enrichment with 90-day window
python3 tenable_product_drivers.py --config config.yaml --window-days 90

# Asset inventory collection
python3 crowdstrike_pull_assets.py --config config.yaml
python3 tenable_pull_assets.py --config config.yaml

# Cross-source asset matching
python3 asset_match_hostname.py
