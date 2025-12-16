#!/bin/bash
cd /root/tenable-tracker
source venv/bin/activate

# Existing regional trends snapshot
python3 tenable_trend_collector.py --config config.yaml

# New product driver metrics (90-day window)
python3 tenable_product_drivers.py --config config.yaml --window-days 90 --dump-plugin-enrichment

# Asset Collection
python3 crowdstrike_pull_assets.py --config config.yaml
python3 tenable_pull_assets.py --config config.yaml

# Asset Backfill
# python3 asset_backfill_unified.py --config config.yaml

# Match Assets
python3 asset_match_hostname.py

deactivate
