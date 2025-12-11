#!/usr/bin/env python3
import psycopg2
import psycopg2.extras
import yaml
import os
import argparse
from datetime import datetime


############################################################
# Load config + secrets
############################################################
def load_config(path: str):
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_path = os.path.join(os.path.dirname(path), cfg.get("secrets_file", "secrets.yaml"))
    with open(secrets_path, "r") as sf:
        secrets = yaml.safe_load(sf) or {}

    # merge secrets
    if "database" in secrets:
        cfg.setdefault("database", {})
        cfg["database"].update(secrets["database"])

    return cfg


############################################################
# Backfill CS-only rows
############################################################
SQL_BACKFILL_CS = """
WITH cs_dedup AS (
    SELECT DISTINCT ON (lower(trim(hostname)))
        hostname,
        lower(trim(hostname)) AS norm_hostname,
        cs_aid,
        first_seen,
        last_seen,
        platform_name,
        os_version
    FROM asset_inventory.cs_assets_raw
    WHERE hostname IS NOT NULL
      AND hostname <> ''
    -- for each norm_hostname, keep the *most recently seen* device
    ORDER BY lower(trim(hostname)), last_seen DESC
)
INSERT INTO asset_inventory.unified_assets (
    canonical_hostname,
    norm_hostname,
    cs_aid,
    has_cs,
    last_seen_cs,
    first_seen_any,
    last_seen_any,
    platform,
    os_version,
    created_at,
    updated_at
)
SELECT
    hostname,
    norm_hostname,
    cs_aid,
    TRUE,
    last_seen,
    first_seen,
    last_seen,
    platform_name,
    os_version,
    NOW(),
    NOW()
FROM cs_dedup
ON CONFLICT (norm_hostname)
DO UPDATE SET
    cs_aid        = EXCLUDED.cs_aid,
    has_cs        = TRUE,
    last_seen_cs  = GREATEST(asset_inventory.unified_assets.last_seen_cs, EXCLUDED.last_seen_cs),
    first_seen_any = LEAST(
        COALESCE(asset_inventory.unified_assets.first_seen_any, EXCLUDED.first_seen_any),
        EXCLUDED.first_seen_any
    ),
    last_seen_any = GREATEST(
        COALESCE(asset_inventory.unified_assets.last_seen_any, EXCLUDED.last_seen_any),
        EXCLUDED.last_seen_any
    ),
    platform      = COALESCE(asset_inventory.unified_assets.platform, EXCLUDED.platform),
    os_version    = COALESCE(asset_inventory.unified_assets.os_version, EXCLUDED.os_version),
    updated_at    = NOW();
"""


############################################################
# Backfill Tenable-only rows
############################################################
SQL_BACKFILL_TENABLE = """
WITH tn_dedup AS (
    SELECT DISTINCT ON (lower(trim(hostname)))
        hostname,
        lower(trim(hostname)) AS norm_hostname,
        tenable_uuid,
        last_seen
    FROM asset_inventory.tenable_assets_raw
    WHERE hostname IS NOT NULL
      AND hostname <> ''
    ORDER BY lower(trim(hostname)), last_seen DESC
)
INSERT INTO asset_inventory.unified_assets (
    canonical_hostname,
    norm_hostname,
    tenable_uuid,
    has_tenable,
    last_seen_tenable,
    first_seen_any,
    last_seen_any,
    created_at,
    updated_at
)
SELECT
    hostname,
    norm_hostname,
    tenable_uuid,
    TRUE,
    last_seen,
    last_seen,
    last_seen,
    NOW(),
    NOW()
FROM tn_dedup
ON CONFLICT (norm_hostname)
DO UPDATE SET
    tenable_uuid      = EXCLUDED.tenable_uuid,
    has_tenable       = TRUE,
    last_seen_tenable = GREATEST(asset_inventory.unified_assets.last_seen_tenable, EXCLUDED.last_seen_tenable),
    first_seen_any    = LEAST(
        COALESCE(asset_inventory.unified_assets.first_seen_any, EXCLUDED.first_seen_any),
        EXCLUDED.first_seen_any
    ),
    last_seen_any     = GREATEST(
        COALESCE(asset_inventory.unified_assets.last_seen_any, EXCLUDED.last_seen_any),
        EXCLUDED.last_seen_any
    ),
    updated_at        = NOW();
"""


############################################################
# Count summary
############################################################
SQL_SUMMARY = """
SELECT
  COUNT(*) AS total_unified,
  COUNT(*) FILTER (WHERE has_cs) AS with_cs,
  COUNT(*) FILTER (WHERE has_tenable) AS with_tenable,
  COUNT(*) FILTER (WHERE has_cs AND has_tenable) AS with_both
FROM asset_inventory.unified_assets;
"""


############################################################
# Main execution
############################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    db = cfg["database"]
    conn_str = f"host={db['host']} port={db['port']} dbname={db['name']} user={db['user']} password={db['password']}"

    conn = psycopg2.connect(conn_str)
    cur = conn.cursor()

    print("[BACKFILL] Inserting CS-only unified assets…")
    cur.execute(SQL_BACKFILL_CS)
    print(f"[BACKFILL] Added {cur.rowcount} new unified rows from CS")

    print("[BACKFILL] Inserting Tenable-only unified assets…")
    cur.execute(SQL_BACKFILL_TENABLE)
    print(f"[BACKFILL] Added {cur.rowcount} new unified rows from Tenable")

    conn.commit()

    print("\n[BACKFILL] Summary after backfill:")
    cur.execute(SQL_SUMMARY)
    total_unified, with_cs, with_tenable, with_both = cur.fetchone()

    print(f"  Total unified assets:    {total_unified}")
    print(f"  With CrowdStrike:        {with_cs}")
    print(f"  With Tenable:            {with_tenable}")
    print(f"  With both:               {with_both}")

    cur.close()
    conn.close()
    print("[BACKFILL] Done.")


if __name__ == "__main__":
    main()
