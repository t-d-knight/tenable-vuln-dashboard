#!/usr/bin/env python3
import argparse
import os
import re
from typing import Dict, Optional, Tuple, List, Any

import psycopg2
import psycopg2.extras
import yaml


# ----------------------------
# Helpers
# ----------------------------

def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = os.path.dirname(os.path.abspath(path))
        secrets_path = os.path.join(base_dir, secrets_rel)
        with open(secrets_path, "r") as sf:
            secrets = yaml.safe_load(sf) or {}

        if "database" in secrets:
            cfg.setdefault("database", {})
            cfg["database"].update(secrets["database"])

    return cfg


def pg_connect(cfg: Dict[str, Any]):
    db = cfg.get("database", {})
    return psycopg2.connect(
        host=db.get("host", "127.0.0.1"),
        port=db.get("port", 5432),
        dbname=db.get("name", "tenable_trends"),
        user=db.get("user", "tenable_trends_user"),
        password=db.get("password"),
    )


_hostname_junk = re.compile(r"[^a-z0-9\-]+")

def norm_hostname(host: Optional[str]) -> Optional[str]:
    """
    Normalise hostname so:
      - lower
      - strip whitespace
      - remove domain part (keep left-most label)
      - remove weird chars
    """
    if not host:
        return None
    h = host.strip().lower()
    if not h:
        return None
    # if FQDN, keep just first label (you can change this if you want fqdn matching)
    if "." in h:
        h = h.split(".", 1)[0]
    h = _hostname_junk.sub("", h)
    return h or None


def log_conflict(cur, *, match_method: str, norm: Optional[str], cs_aid: Optional[str], tenable_uuid: Optional[str],
                 conflict_type: str, unified_ids: Optional[List[int]] = None, details: Optional[dict] = None) -> None:
    cur.execute(
        """
        INSERT INTO asset_inventory.asset_match_conflicts
            (match_method, norm_hostname, cs_aid, tenable_uuid, conflict_type, unified_ids, details)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s::jsonb)
        """,
        (
            match_method,
            norm,
            cs_aid,
            tenable_uuid,
            conflict_type,
            unified_ids,
            psycopg2.extras.Json(details or {}),
        )
    )


# ----------------------------
# DB table sanity (non-destructive)
# ----------------------------

def ensure_conflict_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_inventory.asset_match_conflicts (
            id               BIGSERIAL PRIMARY KEY,
            detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            match_method     TEXT NOT NULL,
            norm_hostname    TEXT,
            cs_aid           TEXT,
            tenable_uuid     TEXT,
            conflict_type    TEXT NOT NULL,
            unified_ids      BIGINT[] NULL,
            details          JSONB
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_match_conflicts_detected_at "
        "ON asset_inventory.asset_match_conflicts (detected_at);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_match_conflicts_norm_hostname "
        "ON asset_inventory.asset_match_conflicts (norm_hostname);"
    )


# ----------------------------
# Unified linking / merging
# ----------------------------

def fetch_unified_rows(cur, norm: Optional[str], cs_aid: Optional[str], tenable_uuid: Optional[str]) -> List[dict]:
    """
    Return any unified_assets rows that match ANY of:
      - cs_aid
      - tenable_uuid
      - norm_hostname
    """
    cur.execute(
        """
        SELECT id, cs_aid, tenable_uuid, norm_hostname, has_cs, has_tenable, has_sccm,
               created_at, updated_at, last_seen_any
        FROM asset_inventory.unified_assets
        WHERE (%s IS NOT NULL AND cs_aid = %s)
           OR (%s IS NOT NULL AND tenable_uuid = %s)
           OR (%s IS NOT NULL AND norm_hostname = %s)
        """,
        (cs_aid, cs_aid, tenable_uuid, tenable_uuid, norm, norm)
    )
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def pick_winner(rows: List[dict]) -> dict:
    """
    Choose which unified_assets row becomes the winner when merging.
    Higher score wins.
    """
    def score(r: dict) -> int:
        s = 0
        s += 2 if r.get("has_cs") else 0
        s += 2 if r.get("has_tenable") else 0
        s += 1 if r.get("has_sccm") else 0
        s += 1 if r.get("cs_aid") else 0
        s += 1 if r.get("tenable_uuid") else 0
        s += 1 if r.get("norm_hostname") else 0
        s += 1 if r.get("last_seen_any") else 0
        return s

    return sorted(rows, key=score, reverse=True)[0]


def rehome_foreign_keys(cur, winner_id: int, loser_id: int) -> None:
    """
    Move any raw table FK references from loser -> winner.
    """
    # CrowdStrike
    cur.execute(
        """
        UPDATE asset_inventory.cs_assets_raw
        SET unified_asset_id = %s
        WHERE unified_asset_id = %s
        """,
        (winner_id, loser_id)
    )
    # Tenable
    cur.execute(
        """
        UPDATE asset_inventory.tenable_assets_raw
        SET unified_asset_id = %s
        WHERE unified_asset_id = %s
        """,
        (winner_id, loser_id)
    )
    # If you also use tn_assets_raw, uncomment:
    # cur.execute(
    #     """
    #     UPDATE asset_inventory.tn_assets_raw
    #     SET unified_asset_id = %s
    #     WHERE unified_asset_id = %s
    #     """,
    #     (winner_id, loser_id)
    # )
    # SCCM
    cur.execute(
        """
        UPDATE asset_inventory.sccm_assets_raw
        SET unified_asset_id = %s
        WHERE unified_asset_id = %s
        """,
        (winner_id, loser_id)
    )


def merge_unified_rows(cur, rows: List[dict], norm: Optional[str], cs_aid: Optional[str], tenable_uuid: Optional[str]) -> int:
    """
    Merge multiple unified_assets rows into one. Returns winner_id.
    """
    winner = pick_winner(rows)
    winner_id = int(winner["id"])
    loser_ids = [int(r["id"]) for r in rows if int(r["id"]) != winner_id]

    log_conflict(
        cur,
        match_method="hostname",
        norm=norm,
        cs_aid=cs_aid,
        tenable_uuid=tenable_uuid,
        conflict_type="MULTI_ROW_MERGE",
        unified_ids=[int(r["id"]) for r in rows],
        details={"winner_id": winner_id, "loser_ids": loser_ids},
    )

    # Re-home FKs then delete losers
    for lid in loser_ids:
        rehome_foreign_keys(cur, winner_id, lid)
        cur.execute("DELETE FROM asset_inventory.unified_assets WHERE id = %s", (lid,))

    return winner_id


def safe_update_unified(cur, unified_id: int, *, norm: Optional[str], cs_aid: Optional[str], tenable_uuid: Optional[str]) -> None:
    """
    Update winner row WITHOUT overwriting a different existing unique value.
    """
    cur.execute(
        """
        SELECT id, cs_aid, tenable_uuid, norm_hostname
        FROM asset_inventory.unified_assets
        WHERE id = %s
        FOR UPDATE
        """,
        (unified_id,)
    )
    row = cur.fetchone()
    if not row:
        return

    existing_cs, existing_tn, existing_norm = row[1], row[2], row[3]

    # If the row already has different IDs, don't overwrite — log + return.
    if cs_aid and existing_cs and existing_cs != cs_aid:
        log_conflict(
            cur,
            match_method="hostname",
            norm=norm,
            cs_aid=cs_aid,
            tenable_uuid=tenable_uuid,
            conflict_type="CS_AID_ALREADY_LINKED",
            unified_ids=[unified_id],
            details={"existing_cs_aid": existing_cs, "attempted_cs_aid": cs_aid},
        )
        cs_aid = None  # prevent overwrite

    if tenable_uuid and existing_tn and existing_tn != tenable_uuid:
        log_conflict(
            cur,
            match_method="hostname",
            norm=norm,
            cs_aid=cs_aid,
            tenable_uuid=tenable_uuid,
            conflict_type="TENABLE_UUID_ALREADY_LINKED",
            unified_ids=[unified_id],
            details={"existing_tenable_uuid": existing_tn, "attempted_tenable_uuid": tenable_uuid},
        )
        tenable_uuid = None  # prevent overwrite

    # norm_hostname is unique too — only set if empty OR same
    if norm and existing_norm and existing_norm != norm:
        # don't overwrite; log
        log_conflict(
            cur,
            match_method="hostname",
            norm=norm,
            cs_aid=cs_aid,
            tenable_uuid=tenable_uuid,
            conflict_type="NORM_HOSTNAME_MISMATCH",
            unified_ids=[unified_id],
            details={"existing_norm_hostname": existing_norm, "attempted_norm_hostname": norm},
        )
        norm = None

    cur.execute(
        """
        UPDATE asset_inventory.unified_assets
        SET
            norm_hostname    = COALESCE(%s, norm_hostname),
            cs_aid           = COALESCE(%s, cs_aid),
            tenable_uuid     = COALESCE(%s, tenable_uuid),
            has_cs           = has_cs OR (%s IS NOT NULL),
            has_tenable      = has_tenable OR (%s IS NOT NULL),
            updated_at       = now()
        WHERE id = %s
        """,
        (norm, cs_aid, tenable_uuid, cs_aid, tenable_uuid, unified_id)
    )


def link_by_hostname(cur, norm: str, cs_aid: str, tenable_uuid: str) -> Optional[int]:
    """
    Main safe linker.
    Returns unified_asset_id if linked/created, else None.
    """
    rows = fetch_unified_rows(cur, norm, cs_aid, tenable_uuid)

    # None exist -> create
    if not rows:
        cur.execute(
            """
            INSERT INTO asset_inventory.unified_assets
                (canonical_hostname, norm_hostname, cs_aid, tenable_uuid,
                 has_cs, has_tenable, created_at, updated_at)
            VALUES
                (%s, %s, %s, %s,
                 true, true, now(), now())
            RETURNING id
            """,
            (norm, norm, cs_aid, tenable_uuid)
        )
        return int(cur.fetchone()[0])

    # One exists -> update safely
    if len(rows) == 1:
        uid = int(rows[0]["id"])
        safe_update_unified(cur, uid, norm=norm, cs_aid=cs_aid, tenable_uuid=tenable_uuid)
        return uid

    # Many exist -> merge then update
    winner_id = merge_unified_rows(cur, rows, norm, cs_aid, tenable_uuid)
    safe_update_unified(cur, winner_id, norm=norm, cs_aid=cs_aid, tenable_uuid=tenable_uuid)
    return winner_id


# ----------------------------
# Load raw assets
# ----------------------------

def load_cs_assets(cur) -> Dict[str, str]:
    """
    Returns: norm_hostname -> cs_aid
    If multiple cs_aid share the same norm hostname, first seen wins and conflict is logged.
    """
    cur.execute(
        """
        SELECT cs_aid, hostname
        FROM asset_inventory.cs_assets_raw
        WHERE hostname IS NOT NULL
        """
    )
    out: Dict[str, str] = {}
    for cs_aid, hostname in cur.fetchall():
        n = norm_hostname(hostname)
        if not n:
            continue
        if n in out and out[n] != cs_aid:
            log_conflict(
                cur,
                match_method="hostname",
                norm=n,
                cs_aid=cs_aid,
                tenable_uuid=None,
                conflict_type="DUPLICATE_CS_HOSTNAME",
                unified_ids=None,
                details={"existing_cs_aid": out[n], "new_cs_aid": cs_aid, "raw_hostname": hostname},
            )
            continue
        out[n] = cs_aid
    return out


def load_tenable_assets(cur) -> Dict[str, str]:
    """
    Returns: norm_hostname -> tenable_uuid
    """
    cur.execute(
        """
        SELECT tenable_uuid, COALESCE(hostname, fqdn) AS name
        FROM asset_inventory.tenable_assets_raw
        WHERE COALESCE(hostname, fqdn) IS NOT NULL
        """
    )
    out: Dict[str, str] = {}
    for tenable_uuid, name in cur.fetchall():
        n = norm_hostname(name)
        if not n:
            continue
        if n in out and out[n] != tenable_uuid:
            log_conflict(
                cur,
                match_method="hostname",
                norm=n,
                cs_aid=None,
                tenable_uuid=tenable_uuid,
                conflict_type="DUPLICATE_TENABLE_HOSTNAME",
                unified_ids=None,
                details={"existing_tenable_uuid": out[n], "new_tenable_uuid": tenable_uuid, "raw_name": name},
            )
            continue
        out[n] = tenable_uuid
    return out


# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser(description="Match CrowdStrike + Tenable assets by hostname into unified_assets")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--limit", type=int, default=0, help="limit matches for testing")
    args = ap.parse_args()

    cfg = load_config(args.config)
    conn = pg_connect(cfg)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            ensure_conflict_table(cur)

            print("[MATCH] Loading CrowdStrike assets…")
            cs_idx = load_cs_assets(cur)
            print(f"[MATCH] CS hostnames indexed: {len(cs_idx)}")

            print("[MATCH] Loading Tenable assets…")
            tn_idx = load_tenable_assets(cur)
            print(f"[MATCH] Tenable hostnames indexed: {len(tn_idx)}")

            shared = sorted(set(cs_idx.keys()) & set(tn_idx.keys()))
            print(f"[MATCH] Shared hostnames: {len(shared)}")

            count = 0
            for n in shared:
                cs_aid = cs_idx[n]
                tn_uuid = tn_idx[n]

                # Important: do each link inside the same transaction, but keep it resilient.
                uid = link_by_hostname(cur, n, cs_aid, tn_uuid)
                if uid:
                    # Optionally backfill unified_asset_id onto raw rows (handy for later joins)
                    cur.execute(
                        "UPDATE asset_inventory.cs_assets_raw SET unified_asset_id=%s WHERE cs_aid=%s",
                        (uid, cs_aid)
                    )
                    cur.execute(
                        "UPDATE asset_inventory.tenable_assets_raw SET unified_asset_id=%s WHERE tenable_uuid=%s",
                        (uid, tn_uuid)
                    )

                count += 1
                if args.limit and count >= args.limit:
                    break

            conn.commit()
            print(f"[MATCH] Completed hostname linking for {count} matches.")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
