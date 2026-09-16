#!/usr/bin/env python3
"""
scanner.py - Static scanner for agentic skill files.

Input:  One skill directory (--skill) or a parent directory (--dir) containing
        multiple skill directories.
Output: For each skill, a verdict (Benign / Suspicious / Malicious) and reasoning.

Usage:
  python3 scanner.py --skill ../skills/malicious/technique-1-embedded-exfil
  python3 scanner.py --dir ../skills/benign
  python3 scanner.py --dir ../skills/malicious
  python3 scanner.py --dir ../skills       # scans all subdirectories recursively
"""

import argparse
import os
import sys
import json

from rules import ALL_RULES


def find_skill_dirs(path):
    """
    Find all directories containing a SKILL.md file under the given path.
    If path itself contains a SKILL.md, return just that path.
    """
    skill_dirs = []

    if os.path.isfile(os.path.join(path, "SKILL.md")):
        return [path]

    for root, dirs, files in os.walk(path):
        if "SKILL.md" in files:
            skill_dirs.append(root)

    return sorted(skill_dirs)


def collect_skill_text(skill_dir):
    """
    Collect all text content from a skill directory:
    - SKILL.md (always)
    - Any .sh, .py, .js, .rb, .pl files in the directory tree
    - Any .md, .txt, .yaml, .yml, .json files in the directory tree

    Returns a dict mapping relative file paths to their text content.
    """
    files = {}
    scannable_extensions = {
        '.md', '.txt', '.sh', '.py', '.js', '.rb', '.pl',
        '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini',
        '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
    }

    for root, dirs, filenames in os.walk(skill_dir):
        for fname in filenames:
            _, ext = os.path.splitext(fname)
            if ext.lower() in scannable_extensions or fname == 'Makefile' or fname == 'Dockerfile':
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, skill_dir)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        files[rel] = f.read()
                except (PermissionError, OSError):
                    pass

    return files


def scan_skill(skill_dir):
    """
    Scan a single skill directory. Returns a result dict:
    {
        "skill": <skill directory name>,
        "path": <full path>,
        "verdict": "Benign" | "Suspicious" | "Malicious",
        "findings": [{"severity": ..., "rule": ..., "file": ..., "detail": ...}, ...],
    }
    """
    skill_name = os.path.basename(os.path.normpath(skill_dir))
    files = collect_skill_text(skill_dir)

    all_findings = []

    for rel_path, content in files.items():
        for rule_name, rule_fn in ALL_RULES:
            results = rule_fn(content)
            for severity, detail in results:
                all_findings.append({
                    "severity": severity,
                    "rule": rule_name,
                    "file": rel_path,
                    "detail": detail,
                })

    # Determine overall verdict
    severities = [f["severity"] for f in all_findings]
    if "MALICIOUS" in severities:
        verdict = "Malicious"
    elif "SUSPICIOUS" in severities:
        verdict = "Suspicious"
    else:
        verdict = "Benign"

    return {
        "skill": skill_name,
        "path": os.path.abspath(skill_dir),
        "verdict": verdict,
        "findings": all_findings,
    }


def print_result(result, verbose=True):
    """Pretty-print a scan result."""
    verdict = result["verdict"]

    # Color codes
    colors = {
        "Benign": "\033[92m",     # green
        "Suspicious": "\033[93m", # yellow
        "Malicious": "\033[91m",  # red
    }
    reset = "\033[0m"
    color = colors.get(verdict, "")

    print(f"\n{'='*70}")
    print(f"  Skill:   {result['skill']}")
    print(f"  Path:    {result['path']}")
    print(f"  Verdict: {color}{verdict}{reset}")

    if result["findings"] and verbose:
        print(f"  Findings ({len(result['findings'])}):")
        for f in result["findings"]:
            sev_color = colors.get("Malicious" if f["severity"] == "MALICIOUS" else "Suspicious", "")
            print(f"    [{sev_color}{f['severity']}{reset}] ({f['rule']}) in {f['file']}:")
            print(f"      {f['detail']}")
    elif not result["findings"]:
        print(f"  No findings. All rules passed.")

    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(
        description="Static scanner for agentic skill files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--skill", help="Path to a single skill directory")
    group.add_argument("--dir", help="Path to a parent directory containing skill subdirectories")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--quiet", action="store_true", help="Only show verdict, not findings detail")

    args = parser.parse_args()

    if args.skill:
        target = args.skill
        if not os.path.isdir(target):
            print(f"Error: {target} is not a directory.", file=sys.stderr)
            sys.exit(1)
        skill_dirs = [target]
    else:
        target = args.dir
        if not os.path.isdir(target):
            print(f"Error: {target} is not a directory.", file=sys.stderr)
            sys.exit(1)
        skill_dirs = find_skill_dirs(target)

    if not skill_dirs:
        print(f"No skills found (no SKILL.md files) under {target}", file=sys.stderr)
        sys.exit(1)

    results = []
    for sd in skill_dirs:
        result = scan_skill(sd)
        results.append(result)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\nScanning {len(skill_dirs)} skill(s)...")
        for r in results:
            print_result(r, verbose=not args.quiet)

        # Summary
        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        verdicts = {"Benign": 0, "Suspicious": 0, "Malicious": 0}
        for r in results:
            verdicts[r["verdict"]] += 1
        for v, count in verdicts.items():
            print(f"  {v}: {count}")
        print(f"  Total: {len(results)}")
        print()

    # Exit code: 0 if all benign, 1 if any suspicious/malicious
    if any(r["verdict"] != "Benign" for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
