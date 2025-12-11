#!/usr/bin/env python3
"""
Basic asset matcher: CrowdStrike <-> Tenable via normalised hostname.

- Reads DB config from config.yaml + secrets.yaml
- Normalises hostnames (lowercase, strip domain)
- Links cs_assets_raw and tn_assets_raw into unified_assets
"""

import os
from typing import Dict, Any, Optional

import psycopg2
import psycopg2.extras
import yaml


############################################################
# Config & DB helpers
############################################################

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = os.path.dirname(os.path.abspath(path))
        secrets_path = os.path.join(base_dir, secrets_rel)
        if not os.path.isfile(secrets_path):
            raise FileNotFoundError(f"Secrets file not found: {secrets_path}")

        with open(secrets_path, "r") as sf:
            secrets = yaml.safe_load(sf) or {}

        # merge DB creds
        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

    return cfg


def get_pg_conn(cfg: Dict[str, Any]):
    db = cfg["database"]
    dsn = (
        f"host={db['host']} port={db['port']} "
        f"dbname={db['name']} user={db['user']} password={db['password']}"
    )
    return psycopg2.connect(dsn)


############################################################
# Normalisation helpers
############################################################

def normalise_hostname(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = name.strip()
    if not name:
        return None
    # drop domain: foo.bar.local -> foo
    base = name.split(".")[0]
    base = base.strip().lower()
    return base or None


############################################################
# Matching logic
############################################################

def upsert_unified_for_pair(cur, norm_hostname: str, cs_aid: str, tn_uuid: str):
    """
    Create or update a unified asset row based on a normalised hostname,
    wiring in the CrowdStrike AID and Tenable UUID.

    Uses your existing schema:
      - norm_hostname (unique)
      - canonical_hostname
      - cs_aid, tenable_uuid
      - has_cs, has_tenable, updated_at
    """
    cur.execute(
        """
        INSERT INTO asset_inventory.unified_assets AS u (
            norm_hostname,
            canonical_hostname,
            cs_aid,
            tenable_uuid,
            has_cs,
            has_tenable
        )
        VALUES (%s, %s, %s, %s, TRUE, TRUE)
        ON CONFLICT (norm_hostname)
        DO UPDATE
        SET
            cs_aid        = COALESCE(u.cs_aid, EXCLUDED.cs_aid),
            tenable_uuid  = COALESCE(u.tenable_uuid, EXCLUDED.tenable_uuid),
            has_cs        = u.has_cs OR EXCLUDED.has_cs,
            has_tenable   = u.has_tenable OR EXCLUDED.has_tenable,
            updated_at    = NOW();
        """,
        # For now, just use the normalised hostname as the canonical name too.
        (norm_hostname, norm_hostname, cs_aid, tn_uuid),
    )

    unified_id = cur.fetchone()[0]

    if cs_aid:
        cur.execute(
            """
            UPDATE asset_inventory.cs_assets_raw
            SET unified_asset_id = %s
            WHERE cs_aid = %s;
            """,
            (unified_id, cs_aid),
        )

    if tn_uuid:
        cur.execute(
            """
            UPDATE asset_inventory.tn_assets_raw
            SET unified_asset_id = %s
            WHERE tn_uuid = %s;
            """,
            (unified_id, tn_uuid),
        )

    return unified_id


def main():
    cfg = load_config("config.yaml")
    conn = get_pg_conn(cfg)
    conn.autocommit = False
    cur = conn.cursor()

    print("[MATCH] Loading CrowdStrike assets…")
    cur.execute(
        """
        SELECT cs_aid, hostname
        FROM asset_inventory.cs_assets_raw
        WHERE hostname IS NOT NULL
        """
    )
    cs_rows = cur.fetchall()

    cs_by_norm: Dict[str, list[str]] = {}
    for cs_aid, hostname in cs_rows:
        norm = normalise_hostname(hostname)
        if not norm:
            continue
        cs_by_norm.setdefault(norm, []).append(cs_aid)

    print(f"[MATCH] CS hostnames indexed: {len(cs_by_norm)}")

    print("[MATCH] Loading Tenable assets…")
    cur.execute(
        """
        SELECT tn_uuid, hostname, fqdn, netbios_name
        FROM asset_inventory.tn_assets_raw
        """
    )
    tn_rows = cur.fetchall()

    matched_count = 0
    no_match_count = 0

    for tn_uuid, tn_host, tn_fqdn, tn_netbios in tn_rows:
        # try fqdn -> hostname -> netbios in that order
        norm = (
            normalise_hostname(tn_fqdn)
            or normalise_hostname(tn_host)
            or normalise_hostname(tn_netbios)
        )
        if not norm:
            no_match_count += 1
            continue

        cs_list = cs_by_norm.get(norm)
        if not cs_list:
            no_match_count += 1
            continue

        # for now, just link to the first CS asset with that hostname
        cs_aid = cs_list[0]

        upsert_unified_for_pair(cur, norm, cs_aid, tn_uuid)
        matched_count += 1

        if matched_count % 1000 == 0:
            conn.commit()
            print(f"[MATCH] {matched_count} Tenable assets matched so far…")

    conn.commit()
    conn.close()

    print(f"[MATCH] Done. Matched Tenable assets: {matched_count}")
    print(f"[MATCH] Tenable assets with no hostname-based match: {no_match_count}")


if __name__ == "__main__":
    main()
