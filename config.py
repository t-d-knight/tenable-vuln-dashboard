#!/usr/bin/env python3
"""Shared config loader: config.yaml + gitignored secrets.yaml."""
import os
from typing import Any, Dict

import yaml


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

        for section in ("tenable", "crowdstrike", "database"):
            if section in secrets:
                cfg.setdefault(section, {})
                cfg[section].update(secrets[section])

    return cfg
