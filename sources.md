# Sources

## Agent framework documentation

- Google Antigravity documentation: https://ai.google.dev/gemini-api/docs/antigravity-agent
- Google Antigravity Skills tutorial (Romin Irani, Google Cloud Community): https://medium.com/google-cloud/tutorial-getting-started-with-antigravity-skills-864041811e0d
- Antigravity Skills format and structure: https://ai.google.dev/gemini-api/docs/managed-agents-quickstart
- Agent Skills specification (Anthropic): https://agentskills.io/home

## Security references

- OWASP Agentic AI Threats - Top 10: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

## Own work

- All scanner rules, benign skills, and malicious skills were authored for this exercise
- Runtime detection logic was designed based on analysis of the three malicious techniques, not sourced from an existing tool
- The cron-lister false positive and its fix were discovered through automated testing against the benign baseline
- Skills were loaded and tested in Google Antigravity (desktop app, Gemini 3.8 Flash) to confirm discovery and invocation
