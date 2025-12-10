#!/bin/bash
cd /root/tenable-tracker
source venv/bin/activate
python3 tenable_trend_collector.py >> collector.log 2>&1
python3 tenable_product_drivers.py --config config.yaml >> product_drivers.log 2>&1
