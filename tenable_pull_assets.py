#!/usr/bin/env python3
import requests
import psycopg2
import psycopg2.extras
import os, yaml, time
from datetime import datetime
from typing import Dict, Any

############################################################
# Load config + secrets
############################################################
def load_config(path="config.yaml") -> Dict[str, Any]:
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}

    secrets_path = os.path.join(os.path.dirname(path), cfg.get("secrets_file"))
    with open(secrets_path) as f:
        secrets = yaml.safe_load(f) or {}

    cfg["tenable"].update(secrets.get("tenable", {}))
    cfg["database"].update(secrets.get("database", {}))

    return cfg


############################################################
# Tenable helper
############################################################
def tenable_get_assets(cfg, limit=2000):
    headers = {
        "X-ApiKeys": f"accessKey={cfg['tenable']['access_key']};secretKey={cfg['tenable']['secret_key']}"
    }

    url = f"{cfg['tenable']['base_url']}/assets"

    assets = []
    offset = 0

    while True:
        params = {"limit": limit, "offset": offset}
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()

        chunk = data.get("assets", [])
        if not chunk:
            break

        assets.extend(chunk)

        print(f"[TN] offset={offset}, got {len(chunk)} assets")

        if len(chunk) < limit:
            break

        offset += limit

    print(f"[TN] Total assets collected: {len(assets)}")
    return assets


############################################################
# Upsert Tenable assets
############################################################
def upsert_tenable(cur, a):
    cur.execute(
        """
        INSERT INTO asset_inventory.tenable_assets_raw (
            tenable_uuid, hostname, fqdn,
            ipv4_addrs, ipv6_addrs, mac_addrs,
            netbios_name, operating_system,
            last_seen, last_authenticated, sources, raw
        )
        VALUES (
            %(tenable_uuid)s, %(hostname)s, %(fqdn)s,
            %(ipv4_addrs)s, %(ipv6_addrs)s, %(mac_addrs)s,
            %(netbios)s, %(os)s,
            %(last_seen)s, %(last_auth)s, %(sources)s, %(raw)s
        )
        ON CONFLICT (tenable_uuid) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            fqdn = EXCLUDED.fqdn,
            ipv4_addrs = EXCLUDED.ipv4_addrs,
            ipv6_addrs = EXCLUDED.ipv6_addrs,
            mac_addrs = EXCLUDED.mac_addrs,
            netbios_name = EXCLUDED.netbios_name,
            operating_system = EXCLUDED.operating_system,
            last_seen = EXCLUDED.last_seen,
            last_authenticated = EXCLUDED.last_authenticated,
            sources = EXCLUDED.sources,
            raw = EXCLUDED.raw,
            collected_at = NOW()
        ;
        """,
        a
    )


############################################################
# MAIN
############################################################
def main():
    cfg = load_config()

    assets = tenable_get_assets(cfg)

    pg = cfg["database"]
    conn = psycopg2.connect(
        dbname=pg["name"], user=pg["user"], password=pg["password"],
        host=pg["host"], port=pg.get("port", 5432)
    )
    cur = conn.cursor()

    count = 0
    for item in assets:
        mapped = {
            "tenable_uuid": item.get("uuid"),
            "hostname": item.get("hostname"),
            "fqdn": item.get("fqdn"),
            "ipv4_addrs": item.get("ipv4s", []),
            "ipv6_addrs": item.get("ipv6s", []),
            "mac_addrs": item.get("mac_addresses", []),
            "netbios": item.get("netbios_name"),
            "os": item.get("operating_system"),
            "last_seen": item.get("last_seen"),
            "last_auth": item.get("last_authenticated_scan_time"),
            "sources": item.get("sources", []),
            "raw": item
        }

        upsert_tenable(cur, mapped)
        count += 1

    conn.commit()
    conn.close()
    print(f"[TN] Upsert complete. {count} rows written.")


if __name__ == "__main__":
    main()
