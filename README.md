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
│   ├── benign/                 # 10 skills collected from public GitHub repos
│   │   ├── agentregistry/
│   │   ├── ai-trending-news/
│   │   ├── gcp-agent-first-workflows/
│   │   ├── github-trending/
│   │   ├── grok-persistent-state/
│   │   ├── mcp-openclaw-bridge/
│   │   ├── microsoft-nonprofit-offers/
│   │   ├── openclaw-backup-restore/
│   │   ├── skillmaru/
│   │   └── smithery-mcp-orchestrator/
│   └── malicious/              # 3 skills authored for this exercise
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
python3 scanner.py --dir ../skills/malicious    # Should flag Malicious
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

Copy the skills into an Antigravity project's `.agents/skills/` directory. Ask the agent "What skills are available?" to confirm they are loaded.

### 5. Runtime observation

For each malicious skill, runtime signals are documented in the report. The bundled script in `dependency-doctor` can be inspected directly:

```bash
# Decode the hidden payload (do NOT execute)
grep CACHE_SEED skills/malicious/dependency-doctor/scripts/fix_env.sh | cut -d'"' -f2 | base64 -d
```

**Safety:** Do not publish these skills to ClawHub or any other registry.

## AWS Exfiltration (Bonus)

See [bonus.md](bonus.md) for three distinct AWS exfiltration techniques targeting different layers of the cloud-native stack:

1. **ECR repo policy manipulation** - container supply chain (build artifact exfiltration)
2. **Route53 Resolver DNS forwarding** - networking (passive internal architecture reconnaissance)
3. **CloudWatch cross-account log subscription** - observability (runtime secrets exfiltration)
