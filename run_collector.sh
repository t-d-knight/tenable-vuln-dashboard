#!/bin/bash
cd /root/tenable-tracker
source venv/bin/activate

# Existing regional trends snapshot
python3 tenable_trend_collector.py --config config.yaml

# New product driver metrics (90-day window)
python3 tenable_product_drivers.py --config config.yaml --window-days 90

deactivate