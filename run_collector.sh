#!/bin/bash
set -euo pipefail

cd /root/tenable-tracker
source venv/bin/activate

# Existing regional trends snapshot
python3 tenable_trend_collector.py --config config.yaml

# Update Top 10 and product metrics data
python3 fill_daily_product_metrics.py --config config.yaml

# Reclassify product families for latest snapshot (keeps Top 10 clean)
python3 reclassify_product_families.py --config config.yaml

# New product driver metrics (90-day window)
python3 tenable_product_drivers.py --config config.yaml --window-days 90

# Asset Collection
python3 crowdstrike_pull_assets.py --config config.yaml
python3 tenable_pull_assets.py --config config.yaml

# Match Assets
python3 asset_match_hostname.py
