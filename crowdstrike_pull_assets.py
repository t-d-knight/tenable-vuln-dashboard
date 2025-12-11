#!/usr/bin/env python3
import os
import time
import yaml
import requests
import psycopg2
import psycopg2.extras
import argparse
from datetime import datetime
from typing import Dict, Any

# Globals initialised in main()
CS_BASE_URL = None
CS_CLIENT_ID = None
CS_CLIENT_SECRET = None
PG_CONN = None


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

        if "tenable" in secrets:
            cfg.setdefault("tenable", {})
            cfg["tenable"].update(secrets["tenable"])

        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

        if "crowdstrike" in secrets:
            cfg.setdefault("crowdstrike", {})
            cfg["crowdstrike"].update(secrets["crowdstrike"])

    return cfg


############################################################
# CrowdStrike auth + API helpers
############################################################

def cs_auth() -> str:
    global CS_BASE_URL, CS_CLIENT_ID, CS_CLIENT_SECRET
    url = f"{CS_BASE_URL}/oauth2/token"
    r = requests.post(
        url,
        data={
            "client_id": CS_CLIENT_ID,
            "client_secret": CS_CLIENT_SECRET,
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


def cs_get_device_aids(token: str) -> list[str]:
    """Example: pull all AIDs from /devices/queries/devices/v1"""
    headers = {"Authorization": f"Bearer {token}"}
    aids: list[str] = []
    url = f"{CS_BASE_URL}/devices/queries/devices/v1"
    params = {"limit": 500}
    while True:
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()
        aids.extend(data.get("resources", []))
        next_token = data.get("meta", {}).get("pagination", {}).get("after")
        if not next_token:
            break
        params["after"] = next_token
    return aids


def cs_get_device_details(token: str, aids: list[str]) -> list[Dict[str, Any]]:
    """Bulk-resolve AIDs via /devices/entities/devices/v2"""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{CS_BASE_URL}/devices/entities/devices/v2"
    out: list[Dict[str, Any]] = []

    # CrowdStrike API usually limits ids to 100 per request
    CHUNK = 100

    for i in range(0, len(aids), CHUNK):
        chunk = aids[i:i + CHUNK]
        try:
            r = requests.get(url, headers=headers, params={"ids": chunk})
            if r.status_code != 200:
                # Helpful debug if CS gets salty again
                print(f"[CS] Error fetching details batch {i//CHUNK + 1}: "
                      f"status={r.status_code}")
                try:
                    print("[CS] Response:", r.json())
                except Exception:
                    print("[CS] Raw response:", r.text[:500])
                r.raise_for_status()
            data = r.json()
            out.extend(data.get("resources", []))
        except requests.HTTPError as e:
            # Bubble up after logging
            raise

    return out


############################################################
# Postgres upsert helper
############################################################

def upsert_device(cur, dev: dict) -> None:
    """
    Upsert a single CrowdStrike device into asset_inventory.cs_assets_raw
    """
    # Wrap the raw dict so psycopg2 knows to send it as JSONB
    raw_json = psycopg2.extras.Json(dev.get("raw", {}))

    cur.execute(
        """
        INSERT INTO asset_inventory.cs_assets_raw (
            cs_aid,
            hostname,
            domain,
            serial_number_raw,
            platform_name,
            os_version,
            local_ip_addresses,
            mac_addresses,
            first_seen,
            last_seen,
            raw,
            collected_at
        )
        VALUES (
            %(aid)s,
            %(hostname)s,
            %(domain)s,
            %(serial)s,
            %(platform)s,
            %(os_version)s,
            %(ips)s,
            %(macs)s,
            %(first_seen)s,
            %(last_seen)s,
            %(raw)s,
            NOW()
        )
        ON CONFLICT (cs_aid) DO UPDATE
        SET
            hostname          = EXCLUDED.hostname,
            domain            = EXCLUDED.domain,
            serial_number_raw = EXCLUDED.serial_number_raw,
            platform_name     = EXCLUDED.platform_name,
            os_version        = EXCLUDED.os_version,
            local_ip_addresses= EXCLUDED.local_ip_addresses,
            mac_addresses     = EXCLUDED.mac_addresses,
            -- keep earliest first_seen and latest last_seen
            first_seen        = LEAST(asset_inventory.cs_assets_raw.first_seen, EXCLUDED.first_seen),
            last_seen         = GREATEST(asset_inventory.cs_assets_raw.last_seen, EXCLUDED.last_seen),
            raw               = EXCLUDED.raw,
            collected_at      = NOW();
        """,
        {
            "aid": dev.get("aid"),
            "hostname": dev.get("hostname"),
            "domain": dev.get("domain"),
            "serial": dev.get("serial"),
            "platform": dev.get("platform"),
            "os_version": dev.get("os_version"),
            "ips": dev.get("ips") or [],
            "macs": dev.get("macs") or [],
            "first_seen": dev.get("first_seen"),
            "last_seen": dev.get("last_seen"),
            "raw": raw_json,
        },
    )


############################################################
# Main
############################################################
def main():
    print("[CS] Authenticating...")
    token = cs_auth()

    print("[CS] Pulling AID list...")
    aids = cs_get_device_aids(token)
    print(f"[CS] Found {len(aids)} devices")

    print("[CS] Fetching full details...")
    devices = cs_get_device_details(token, aids)
    print(f"[CS] Retrieved {len(devices)} records")

    conn = psycopg2.connect(PG_CONN)
    cur = conn.cursor()

    count = 0
    for d in devices:
        # Normalise IPs and MACs to lists for TEXT[] columns
        ips_raw = d.get("local_ip")
        if ips_raw is None:
            ips = []
        elif isinstance(ips_raw, list):
            ips = ips_raw
        else:
            ips = [ips_raw]

        macs_raw = d.get("mac_address")
        if macs_raw is None:
            macs = []
        elif isinstance(macs_raw, list):
            macs = macs_raw
        else:
            macs = [macs_raw]

        mapped = {
            "aid": d.get("device_id"),
            "hostname": d.get("hostname"),
            "domain": d.get("machine_domain"),
            "serial": d.get("serial_number"),
            "platform": d.get("platform_name"),
            "os_version": d.get("os_version"),
            "ips": ips,
            "macs": macs,
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "raw": d,
        }

        upsert_device(cur, mapped)
        count += 1

    conn.commit()
    conn.close()
    print(f"[CS] Upsert complete. {count} rows written.")



if __name__ == "__main__":
    main()
