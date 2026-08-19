#!/bin/bash
set -euo pipefail

# --- CONFIG ----------------------------------------------------
APP_DIR="/root/tenable-tracker"
VENV_BIN="$APP_DIR/venv/bin"
LOG_DIR="$APP_DIR/logs"

DB_NAME="tenable_trends"
DB_USER="tenable_trends_user"

# How long to keep stuff
RETENTION_DAYS_DB=540       # match your reporting.retention_days
RETENTION_DAYS_LOGS=30      # app logs
RETENTION_DAYS_TMP=7        # temp files

TIMESTAMP="$(date -Iseconds)"
echo "[$TIMESTAMP] ===== Tenable tracker maintenance start ====="

# --- 1) Prune old DB rows --------------------------------------
echo "[$TIMESTAMP] Pruning old database rows (>${RETENTION_DAYS_DB} days)…"

psql -U "$DB_USER" -d "$DB_NAME" <<SQL
-- Main product metrics table (we know this exists)
DELETE FROM daily_product_metrics
WHERE snapshot_date::date < CURRENT_DATE - INTERVAL '${RETENTION_DAYS_DB} days';

-- If you add other snapshot tables, copy this pattern:
-- DELETE FROM daily_site_metrics
-- WHERE snapshot_date::date < CURRENT_DATE - INTERVAL '${RETENTION_DAYS_DB} days';
--
-- DELETE FROM daily_remote_summary
-- WHERE snapshot_date::date < CURRENT_DATE - INTERVAL '${RETENTION_DAYS_DB} days';
SQL

# --- 2) Reclassify product families (to keep history clean) ----
echo "[$TIMESTAMP] Reclassifying product families…"

"$VENV_BIN/python3" "$APP_DIR/reclassify_product_families.py" \
  --config "$APP_DIR/config.yaml"

# --- 3) VACUUM / ANALYZE to keep bloat down --------------------
echo "[$TIMESTAMP] Running vacuumdb…"
vacuumdb -U "$DB_USER" -d "$DB_NAME" -z

# --- 4) Rotate app logs ----------------------------------------
echo "[$TIMESTAMP] Cleaning old app logs (> ${RETENTION_DAYS_LOGS} days)…"
mkdir -p "$LOG_DIR"
find "$LOG_DIR" -type f -name "*.log" -mtime +$RETENTION_DAYS_LOGS -delete

# --- 5) Clean temp Tenable / export files ----------------------
# Adjust these paths if you stash temp export chunks anywhere
echo "[$TIMESTAMP] Cleaning temp files (> ${RETENTION_DAYS_TMP} days)…"
find "$APP_DIR" -maxdepth 2 -type f \( -name "*.tmp" -o -name "*.json" -o -name "*.gz" \) \
     -mtime +$RETENTION_DAYS_TMP -print -delete || true

# --- 6) (Optional) journalctl trim – uncomment if needed -------
# echo "[$TIMESTAMP] Trimming systemd journal to 500M…"
# journalctl --vacuum-size=500M

echo "[$TIMESTAMP] ===== Tenable tracker maintenance complete ====="