#!/usr/bin/env python3
import requests
import psycopg2
import psycopg2.extras
import time
import yaml
from datetime import datetime

############################################################
# Load Config
############################################################
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)

CS_CLIENT_ID = cfg["crowdstrike"]["client_id"]
CS_CLIENT_SECRET = cfg["crowdstrike"]["client_secret"]
CS_BASE_URL = cfg["crowdstrike"]["base_url"]

PG_CONN = cfg["database"]["connection"]

############################################################
# Authenticate to CrowdStrike
############################################################
def cs_auth():
    url = f"{CS_BASE_URL}/oauth2/token"
    r = requests.post(url, data={
        "client_id": CS_CLIENT_ID,
        "client_secret": CS_CLIENT_SECRET
    })
    r.raise_for_status()
    return r.json()["access_token"]

############################################################
# Get full device AID list
############################################################
def cs_get_device_aids(token):
    aids = []
    offset = None

    while True:
        params = {"limit": 5000}
        if offset:
            params["offset"] = offset

        r = requests.get(
            f"{CS_BASE_URL}/devices/queries/devices/v1",
            headers={"Authorization": f"Bearer {token}"},
            params=params
        )
        r.raise_for_status()
        data = r.json()
        aids.extend(data.get("resources", []))

        offset = data.get("meta", {}).get("pagination", {}).get("offset")
        if not offset:
            break

    return aids

############################################################
# Get device details in batches
############################################################
def cs_get_device_details(token, aids):
    all_devices = []
    chunk = 100

    for i in range(0, len(aids), chunk):
        batch = aids[i:i+chunk]
        r = requests.post(
            f"{CS_BASE_URL}/devices/entities/devices/v2",
            headers={"Authorization": f"Bearer {token}"},
            json={"ids": batch}
        )
        r.raise_for_status()
        all_devices.extend(r.json().get("resources", []))

    return all_devices

############################################################
# Upsert into PostgreSQL
############################################################
def upsert_device(cur, d):

    cur.execute(
        """
        INSERT INTO asset_inventory.cs_assets_raw (
            cs_aid, hostname, domain, serial_number_raw,
            platform_name, os_version,
            local_ip_addresses, mac_addresses,
            first_seen, last_seen,
            raw
        )
        VALUES (
            %(aid)s, %(hostname)s, %(domain)s, %(serial)s,
            %(platform)s, %(os_version)s,
            %(ips)s, %(macs)s,
            %(first_seen)s, %(last_seen)s,
            %(raw)s
        )
        ON CONFLICT (cs_aid)
        DO UPDATE SET
            hostname = EXCLUDED.hostname,
            domain = EXCLUDED.domain,
            serial_number_raw = EXCLUDED.serial_number_raw,
            platform_name = EXCLUDED.platform_name,
            os_version = EXCLUDED.os_version,
            local_ip_addresses = EXCLUDED.local_ip_addresses,
            mac_addresses = EXCLUDED.mac_addresses,
            first_seen = EXCLUDED.first_seen,
            last_seen = EXCLUDED.last_seen,
            raw = EXCLUDED.raw,
            collected_at = NOW();
        """,
        d
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
        mapped = {
            "aid": d.get("device_id"),
            "hostname": d.get("hostname"),
            "domain": d.get("machine_domain"),
            "serial": d.get("serial_number"),
            "platform": d.get("platform_name"),
            "os_version": d.get("os_version"),
            "ips": d.get("local_ip", []),
            "macs": d.get("mac_address", []),
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
