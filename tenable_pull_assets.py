#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import time
from typing import Dict, Any, Iterable, List

import requests
import yaml

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None


# -------------------------------------------------------------------
# CONFIG LOADING (same pattern as trend / product scripts)
# -------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load main config.yaml, then (optionally) merge in secrets.yaml.
    """
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

    return cfg


# -------------------------------------------------------------------
# POSTGRES HELPERS
# -------------------------------------------------------------------

def pg_connect(cfg: Dict[str, Any]):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed in this venv")

    db = cfg.get("database", {})
    return psycopg2.connect(
        host=db.get("host", "127.0.0.1"),
        port=db.get("port", 5432),
        dbname=db.get("name", "tenable_trends"),
        user=db.get("user", "tenable_trends_user"),
        password=db.get("password"),
    )


def init_db(cfg: Dict[str, Any]):
    """
    Ensure asset_inventory schema + tn_assets_raw table exist.
    """
    conn = pg_connect(cfg)
    cur = conn.cursor()

    # Create schema if missing
    cur.execute("""
        CREATE SCHEMA IF NOT EXISTS asset_inventory;
    """)

    # Tenable raw asset table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS asset_inventory.tn_assets_raw (
        tn_uuid            TEXT PRIMARY KEY,
        hostname           TEXT,
        fqdn               TEXT,
        netbios_name       TEXT,
        operating_system   TEXT,
        agent_name         TEXT,
        agent_uuid         TEXT,
        bios_uuid          TEXT,
        hardware_uuid      TEXT,

        ipv4_addrs         TEXT[],
        ipv6_addrs         TEXT[],
        mac_addrs          TEXT[],

        first_seen         TIMESTAMPTZ,
        last_seen          TIMESTAMPTZ,

        tags               JSONB,
        raw                JSONB,

        unified_asset_id   BIGINT REFERENCES asset_inventory.unified_assets(id),

        collected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """)

    conn.commit()
    conn.close()


# -------------------------------------------------------------------
# TENABLE API HELPERS (same style as other scripts)
# -------------------------------------------------------------------

def tenable_session(base_url: str, access_key: str, secret_key: str) -> requests.Session:
    s = requests.Session()
    s.base_url = base_url.rstrip("/")
    s.headers.update({
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s


def start_asset_export(sess: requests.Session) -> str:
    """
    Kick off an ASSETS export with tags. This is analogous to
    fetch_all_assets() in the trend/product scripts but we
    keep the raw asset objects instead of just their tags.
    """
    payload = {
        "include_attributes": ["tags"],
        "chunk_size": 5000,
    }
    print("[TN] Starting asset export...")
    resp = sess.post(f"{sess.base_url}/assets/export", json=payload)
    resp.raise_for_status()
    data = resp.json()
    export_uuid = data.get("export_uuid") or data.get("uuid")
    if not export_uuid:
        raise RuntimeError(f"Asset export UUID missing: {data}")
    print(f"[TN] Asset export UUID: {export_uuid}")
    return export_uuid


def poll_asset_export(sess: requests.Session, uuid: str, interval: int = 5) -> Dict[str, Any]:
    url = f"{sess.base_url}/assets/export/{uuid}/status"
    start = time.time()
    while True:
        resp = sess.get(url)
        resp.raise_for_status()
        status = resp.json()
        elapsed = int(time.time() - start)
        print(
            f"[TN] asset_export {uuid} status={status.get('status')} "
            f"chunks={status.get('chunks_available')} elapsed={elapsed}s"
        )

        if status.get("status") == "FINISHED":
            print("[TN] Asset export FINISHED.")
            return status

        if status.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Asset export failed: {status}")

        time.sleep(interval)


def iter_asset_chunks(sess: requests.Session, uuid: str, chunks) -> Iterable[Dict[str, Any]]:
    for c in chunks:
        print(f"[TN] Fetching asset chunk {c}…")
        resp = sess.get(f"{sess.base_url}/assets/export/{uuid}/chunks/{c}")
        resp.raise_for_status()
        data = resp.json()
        # Some tenants return list, others {assets:[...]}
        if isinstance(data, list):
            assets = data
        else:
            assets = data.get("assets", data)
        for a in assets:
            yield a


# -------------------------------------------------------------------
# NORMALISATION / UPSERT
# -------------------------------------------------------------------

def _to_ts(epoch: Any):
    if epoch is None:
        return None
    try:
        return dt.datetime.utcfromtimestamp(int(epoch))
    except Exception:
        return None


def _to_arr(val) -> List[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    return [str(val)]


def upsert_asset(cur, a: Dict[str, Any]):
    aid = a.get("id") or a.get("uuid")
    if not aid:
        return

    ipv4 = a.get("ipv4") or a.get("ipv4s") or []
    ipv6 = a.get("ipv6") or a.get("ipv6s") or []
    macs = a.get("mac_address") or a.get("mac_addresses") or []

    hostname = None
    hostnames = a.get("hostnames") or []
    if hostnames and isinstance(hostnames, list):
        # pick first non-empty as "primary" hostname
        for h in hostnames:
            if h:
                hostname = str(h)
                break

    fqdn = a.get("fqdn") or a.get("dns_name")

    cur.execute(
        """
        INSERT INTO asset_inventory.tn_assets_raw (
            tn_uuid,
            hostname,
            fqdn,
            netbios_name,
            operating_system,
            agent_name,
            agent_uuid,
            bios_uuid,
            hardware_uuid,
            ipv4_addrs,
            ipv6_addrs,
            mac_addrs,
            first_seen,
            last_seen,
            tags,
            raw,
            collected_at
        )
        VALUES (
            %(tn_uuid)s,
            %(hostname)s,
            %(fqdn)s,
            %(netbios_name)s,
            %(operating_system)s,
            %(agent_name)s,
            %(agent_uuid)s,
            %(bios_uuid)s,
            %(hardware_uuid)s,
            %(ipv4_addrs)s,
            %(ipv6_addrs)s,
            %(mac_addrs)s,
            %(first_seen)s,
            %(last_seen)s,
            %(tags)s,
            %(raw)s,
            NOW()
        )
        ON CONFLICT (tn_uuid)
        DO UPDATE SET
            hostname         = EXCLUDED.hostname,
            fqdn             = EXCLUDED.fqdn,
            netbios_name     = EXCLUDED.netbios_name,
            operating_system = EXCLUDED.operating_system,
            agent_name       = EXCLUDED.agent_name,
            agent_uuid       = EXCLUDED.agent_uuid,
            bios_uuid        = EXCLUDED.bios_uuid,
            hardware_uuid    = EXCLUDED.hardware_uuid,
            ipv4_addrs       = EXCLUDED.ipv4_addrs,
            ipv6_addrs       = EXCLUDED.ipv6_addrs,
            mac_addrs        = EXCLUDED.mac_addrs,
            first_seen       = EXCLUDED.first_seen,
            last_seen        = EXCLUDED.last_seen,
            tags             = EXCLUDED.tags,
            raw              = EXCLUDED.raw,
            collected_at     = NOW();
        """,
                {
            "tn_uuid": aid,
            "hostname": hostname,
            "fqdn": fqdn,
            "netbios_name": a.get("netbios_name"),
            "operating_system": a.get("operating_system"),
            "agent_name": a.get("agent_name"),
            "agent_uuid": a.get("agent_uuid"),
            "bios_uuid": a.get("bios_uuid"),
            "hardware_uuid": a.get("hardware_uuid"),
            "ipv4_addrs": _to_arr(ipv4),
            "ipv6_addrs": _to_arr(ipv6),
            "mac_addrs": _to_arr(macs),
            "first_seen": _to_ts(a.get("first_seen")),
            "last_seen": _to_ts(a.get("last_seen")),

            # 🔹 FIX: wrap tags as JSONB, same as raw
            "tags": psycopg2.extras.Json(a.get("tags") or []),
            "raw": psycopg2.extras.Json(a),
        },

    )


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Pull Tenable assets into asset_inventory.tn_assets_raw via assets/export"
    )
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    ten_cfg = cfg["tenable"]

    init_db(cfg)

    sess = tenable_session(
        ten_cfg["base_url"],
        ten_cfg["access_key"],
        ten_cfg["secret_key"],
    )

    export_uuid = start_asset_export(sess)
    status = poll_asset_export(sess, export_uuid)
    chunks = status.get("chunks_available") or []

    conn = pg_connect(cfg)
    cur = conn.cursor()

    count = 0
    for asset in iter_asset_chunks(sess, export_uuid, chunks):
        upsert_asset(cur, asset)
        count += 1
        if count % 1000 == 0:
            conn.commit()
            print(f"[TN] {count} assets upserted…")

    conn.commit()
    conn.close()
    print(f"[TN] Done. Total Tenable assets upserted: {count}")


if __name__ == "__main__":
    main()
