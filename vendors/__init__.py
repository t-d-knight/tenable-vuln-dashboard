#!/usr/bin/env python3
"""
Adapter registry, keyed by config.yaml's sources[].type. Add a new entry
here when a new vendor adapter (e.g. crowdstrike_em, intune) is implemented.
"""
from vendors import tenable as tenable_adapter

ADAPTERS = {
    "tenable": tenable_adapter,
}
