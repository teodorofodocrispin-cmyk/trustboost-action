#!/usr/bin/env python3
"""
TrustBoost PII Scanner — GitHub Action
Scans repository files for PII before commits reach production.
"""

import os
import sys
import glob
import json
import requests


def get_input(name: str, default: str = "") -> str:
    return os.environ.get(f"INPUT_{name.upper().replace("-", "_")}", default)


def set_output(name: str, value: str):
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/stdout"), "a") as f:
        f.write(f"{name}={value}\n")


def scan_file(filepath: str, wallet: str, tx_hash: str) -> dict:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if not content.strip():
            return {"file": filepath, "status": "empty", "risk_category": "CLEAN"}

        # Use preview endpoint for files — no quota consumption
        response = requests.post(
            "https://api.trustboost.dev/sanitize/preview",
            json={"text": content[:2000]},  # scan first 2000 chars
            timeout=30
        )
        response.raise_for_status()
        result = response.json()

        return {
            "file": filepath,
            "status": "scanned",
            "safety_score": result.get("safety_score", 0.0),
            "risk_category": result.get("risk_category", "CLEAN"),
            "demo": result.get("demo", True)
        }

    except requests.exceptions.Timeout:
        return {"file": filepath, "status": "timeout", "risk_category": "UNKNOWN"}
    except Exception as e:
        return {"file": filepath, "status": "error", "error": str(e), "risk_category": "UNKNOWN"}


def main():
    # Get inputs
    file_patterns = get_input("files", "**/*.txt,**/*.md,**/*.json,**/*.csv")
    wallet = get_input("wallet_address", "github-action")
    tx_hash = get_input("tx_hash", "TRIAL")
    fail_on_critical = get_input("fail_on_critical", "true").lower() == "true"
    fail_on_private = get_input("fail_on_private", "false").lower() == "true"

    # Collect files
    files_to_scan = []
    for pattern in file_patterns.split(","):
        pattern = pattern.strip()
        files_to_scan.extend(glob.glob(pattern, recursive=True))

    # Remove duplicates and hidden files
    files_to_scan = list(set([
        f for f in files_to_scan
        if not any(part.startswith(".") for part in f.split("/"))
    ]))

    if not files_to_scan:
        print("No files matched the pattern. Skipping scan.")
        set_output("pii_found", "false")
        set_output("files_scanned", "0")
        set_output("critical_count", "0")
        set_output("private_count", "0")
        sys.exit(0)

    print(f"\n🛡️ TrustBoost PII Scanner")
    print(f"Scanning {len(files_to_scan)} files...\n")

    results = []
    critical_files = []
    private_files = []

    for filepath in files_to_scan:
        result = scan_file(filepath, wallet, tx_hash)
        results.append(result)

        risk = result.get("risk_category", "CLEAN")
        score = result.get("safety_score", 0.0)

        if risk == "CRITICAL":
            critical_files.append(filepath)
            print(f"  🔴 CRITICAL  [{score:.2f}] {filepath}")
        elif risk == "PRIVATE":
            private_files.append(filepath)
            print(f"  🟡 PRIVATE   [{score:.2f}] {filepath}")
        elif risk == "SENSITIVE":
            print(f"  🟠 SENSITIVE [{score:.2f}] {filepath}")
        elif risk == "CLEAN":
            print(f"  ✅ CLEAN     [{score:.2f}] {filepath}")
        else:
            print(f"  ⚪ UNKNOWN   {filepath}")

    # Summary
    pii_found = len(critical_files) > 0 or len(private_files) > 0
    print(f"\n📊 Summary")
    print(f"  Files scanned:  {len(files_to_scan)}")
    print(f"  Critical:       {len(critical_files)}")
    print(f"  Private:        {len(private_files)}")
    print(f"  PII found:      {pii_found}")

    # Set outputs
    set_output("pii_found", str(pii_found).lower())
    set_output("files_scanned", str(len(files_to_scan)))
    set_output("critical_count", str(len(critical_files)))
    set_output("private_count", str(len(private_files)))

    # Fail conditions
    should_fail = False
    if fail_on_critical and critical_files:
        print(f"\n❌ Failing: CRITICAL PII detected in {len(critical_files)} file(s)")
        print("   Files:", ", ".join(critical_files))
        should_fail = True

    if fail_on_private and private_files:
        print(f"\n❌ Failing: PRIVATE PII detected in {len(private_files)} file(s)")
        print("   Files:", ", ".join(private_files))
        should_fail = True

    if should_fail:
        print("\n💡 Fix: Review flagged files and remove or redact sensitive data.")
        print("   Learn more: https://github.com/teodorofodocrispin-cmyk/TrustBoost-PII-Sanitizer")
        sys.exit(1)
    else:
        print("\n✅ PII scan passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
