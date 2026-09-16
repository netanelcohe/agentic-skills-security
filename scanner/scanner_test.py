#!/usr/bin/env python3
"""
scanner_test.py - Automated test: run the scanner against all skills and
verify expected verdicts.

Usage:
  python3 scanner_test.py
"""

import os
import sys

# Add scanner directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_skill

# Expected verdicts for each skill
EXPECTED = {
    # Benign skills (must all pass as Benign)
    "../skills/benign/git-commit-helper": "Benign",
    "../skills/benign/docker-cleanup": "Benign",
    "../skills/benign/log-rotate": "Benign",
    "../skills/benign/python-venv-setup": "Benign",
    "../skills/benign/disk-usage-report": "Benign",
    "../skills/benign/ssl-cert-check": "Benign",
    "../skills/benign/cron-lister": "Benign",
    "../skills/benign/system-info": "Benign",
    "../skills/benign/file-search": "Benign",
    "../skills/benign/markdown-toc": "Benign",
    # Malicious skills (must be caught)
    "../skills/malicious/log-cleanup-helper": "Malicious",
    "../skills/malicious/dependency-doctor": "Malicious",
    "../skills/malicious/api-docs-assistant": "Malicious",
}


def run_tests():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    passed = 0
    failed = 0
    errors = []

    print("Running scanner validation against all skills...\n")
    print(f"{'Skill':<50} {'Expected':<12} {'Got':<12} {'Result'}")
    print("-" * 90)

    for rel_path, expected in EXPECTED.items():
        skill_path = os.path.normpath(os.path.join(script_dir, rel_path))

        if not os.path.isdir(skill_path):
            print(f"  SKIP: {rel_path} (directory not found)")
            errors.append((rel_path, "NOT FOUND", expected))
            failed += 1
            continue

        result = scan_skill(skill_path)
        actual = result["verdict"]
        skill_name = result["skill"]

        # For malicious skills, accept both Malicious and Suspicious as a "catch"
        # (Suspicious means the scanner flagged it, just not with highest confidence)
        if expected == "Malicious":
            match = actual in ("Malicious", "Suspicious")
        else:
            match = actual == expected

        status = "\033[92mPASS\033[0m" if match else "\033[91mFAIL\033[0m"

        print(f"  {skill_name:<48} {expected:<12} {actual:<12} {status}")

        if match:
            passed += 1
        else:
            failed += 1
            errors.append((skill_name, actual, expected))

            # Show findings detail for failures
            if result["findings"]:
                for f in result["findings"]:
                    print(f"    -> [{f['severity']}] {f['rule']}: {f['detail'][:60]}...")
            else:
                print(f"    -> No findings (expected {expected})")

    print(f"\n{'='*90}")
    print(f"Results: {passed} passed, {failed} failed, {len(EXPECTED)} total")

    if errors:
        print("\nFailures:")
        for name, got, expected in errors:
            print(f"  {name}: expected {expected}, got {got}")

    print()
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
