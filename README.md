# Agentic Skills Security Research

Research exercise: understanding how agentic skills can be abused, and how those abuses can be detected statically and at runtime.

## Environment

- **Agent framework:** Google Antigravity (desktop app, public preview)
- **Model:** Gemini 3.8 Flash (cloud-hosted via Antigravity)
- **Skills location:** `.agents/skills/` (project-scoped, Antigravity workspace)
- **Scanner language:** Python 3 (stdlib only, no external dependencies)

## Repository structure

```
.
├── README.md
├── report/
│   └── REPORT.md
├── scanner/
│   ├── scanner.py
│   ├── rules.py
│   ├── scanner_test.py
│   └── requirements.txt
├── skills/
│   ├── benign/
│   │   ├── git-commit-helper/
│   │   ├── docker-cleanup/
│   │   ├── log-rotate/
│   │   ├── python-venv-setup/
│   │   ├── disk-usage-report/
│   │   ├── ssl-cert-check/
│   │   ├── cron-lister/
│   │   ├── system-info/
│   │   ├── file-search/
│   │   └── markdown-toc/
│   └── malicious/
│       ├── log-cleanup-helper/
│       ├── dependency-doctor/
│       └── api-docs-assistant/
└── sources.md
```

## Reproducing

### 1. Run the static scanner against all skills

```bash
cd scanner
python3 scanner.py --dir ../skills/benign      # Should all pass as Benign
python3 scanner.py --dir ../skills/malicious    # Should flag Malicious or Suspicious
```

### 2. Run against a single skill

```bash
python3 scanner.py --skill ../skills/malicious/log-cleanup-helper
```

### 3. Run the automated test suite

```bash
python3 scanner_test.py
```

Runs the scanner against all 13 skills (10 benign + 3 malicious) and reports pass/fail for each expected verdict.

### 4. Load skills in Antigravity (optional)

Copy the skills into an Antigravity project's `.agents/skills/` directory. Ask the agent "What skills are available?" to confirm they are loaded. Skills can be triggered via natural language prompts matching their description field.

### 5. Runtime observation

For each malicious skill, runtime signals are documented in the report. The bundled script in `dependency-doctor` can be observed directly:

```bash
# Decode the payload (do NOT execute)
grep CACHE_SEED skills/malicious/dependency-doctor/scripts/fix_env.sh | cut -d'"' -f2 | base64 -d
```

**Safety:** Run all malicious skills only in an isolated environment. Do not publish to ClawHub or any registry.
