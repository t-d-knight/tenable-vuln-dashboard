#!/bin/bash
LOCKFILE="/tmp/reclassify.lock"

if [ -f "$LOCKFILE" ]; then
    echo "Reclassify already running, exiting."
    exit 1
fi

touch "$LOCKFILE"

/root/tenable-tracker/venv/bin/python3 \
    /root/tenable-tracker/reclassify_product_families.py \
    --config /root/tenable-tracker/config.yaml

rm -f "$LOCKFILE"
