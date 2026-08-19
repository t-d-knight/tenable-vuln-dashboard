#!/bin/bash
set -euo pipefail

# run_collector.sh
# Daily collection pipeline. Intended to be run via cron:
#   0 2 * * * cd /root/tenable-tracker && ./run_collector.sh >> logs/collector.log 2>&1
#
# NOTE: ingest_findings.py triggers exactly ONE Tenable export job per run
# (previously three separate scripts each triggered their own export for
# overlapping data). On large tenants (50k+ assets, 500k+ findings) expect
# Tenable's side of that single export to take 10-30 minutes -- the poll
# loop inside it is normal, Tenable export jobs are async on their end.

cd /root/tenable-tracker
source venv/bin/activate

# Vendor-agnostic findings ingest (Tenable today; future CrowdStrike Falcon
# Exposure Management / Intune adapters plug in here via config.yaml's
# `sources:` list). Also refreshes the plugin/CVE catalog in the same pass.
python3 ingest_findings.py --config config.yaml

# Derive daily_site_metrics / daily_sla_metrics / daily_product_metrics /
# daily_kev_metrics / daily_mttr_metrics from vuln_findings.
python3 rollup_daily_metrics.py --config config.yaml

# Reclassify product families to keep Top 10 clean after rule changes.
python3 reclassify_product_families.py --config config.yaml

# Refresh the CISA Known Exploited Vulnerabilities catalog.
python3 kev_sync.py --config config.yaml

# Asset Collection
python3 crowdstrike_pull_assets.py --config config.yaml
python3 tenable_pull_assets.py --config config.yaml

# Match Assets
python3 asset_match_hostname.py --config config.yaml
