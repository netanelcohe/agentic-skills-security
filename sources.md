# Sources

## Benign skills (collected from public sources)

- vbrunotech/agent-toolkit: https://github.com/vbrunotech/agent-toolkit
  - Skills used: ai-trending-news, github-trending, openclaw-backup-restore
  - License: Apache-2.0

- igor-holt/openclaw-skills: https://github.com/igor-holt/openclaw-skills
  - Skills used: agentregistry, gcp-agent-first-workflows, grok-persistent-state, mcp-openclaw-bridge, microsoft-nonprofit-offers, skillmaru, smithery-mcp-orchestrator
  - License: MIT-0

## Agent framework documentation

- Google Antigravity documentation: https://ai.google.dev/gemini-api/docs/antigravity-agent
- Google Antigravity Skills tutorial (Romin Irani, Google Cloud Community): https://medium.com/google-cloud/tutorial-getting-started-with-antigravity-skills-864041811e0d
- OpenClaw Skills documentation: https://docs.openclaw.ai/tools/skills
- ClawHub Skill format specification: https://docs.openclaw.ai/clawhub/skill-format
- AgentSkills.io standard: https://agentskills.io/home
- Awesome OpenClaw Skills (curated registry): https://github.com/VoltAgent/awesome-openclaw-skills

## Security references

- OWASP Agentic AI Threats - Top 10: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- ClawHub security notice (341 malicious skills found, Feb 2026): https://clawdocs.org/guides/clawhub

## Own work

- All scanner rules and malicious skills were authored for this exercise
- Runtime detection logic was designed based on analysis of the three malicious techniques
- Scanner iteration (false positives, crontab fix, context-aware URL detection) was discovered through automated testing against the benign baseline
- Skills were loaded and tested in Google Antigravity (desktop app, Gemini 3.8 Flash) to confirm discovery and invocation
