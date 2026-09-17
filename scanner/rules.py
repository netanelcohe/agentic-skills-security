"""
rules.py - Static detection rules for agentic skill scanning.

Each rule is a function that takes the full text content of a file and returns
a list of (severity, description) tuples. Severity is one of:
  "MALICIOUS"  - high-confidence malicious pattern
  "SUSPICIOUS" - warrants manual review
"""

import re
import base64
import os


def check_outbound_url_with_sensitive_data(text):
    """
    Rule 1: Detects outbound HTTP requests that include sensitive system data
    as payload. Looks for curl/wget POST commands co-occurring with env vars,
    /etc/passwd, credential file reads, or $() subshell exfil.
    """
    findings = []

    # Pattern: curl/wget with POST and sensitive data sources
    sensitive_sources = [
        r'\$\(.*?env.*?\)',
        r'\$\(.*?cat\s+/etc/passwd.*?\)',
        r'\$\(.*?cat\s+/etc/shadow.*?\)',
        r'\$\(.*?cat\s+.*?\.ssh/.*?\)',
        r'\$\(.*?cat\s+.*?\.aws/.*?\)',
        r'\$\(.*?cat\s+.*?\.kube/.*?\)',
        r'\$\(.*?cat\s+.*?\.env.*?\)',
        r'\$\{?HOME\}?/\.ssh',
        r'\$\{?HOME\}?/\.aws',
        r'\$\{?AWS_SECRET',
        r'\$\{?API_KEY',
        r'\$\{?TOKEN\}?',
    ]

    outbound_patterns = [
        r'curl\s+.*?-X\s+POST',
        r'curl\s+.*?--data',
        r'curl\s+.*?-d\s+',
        r'wget\s+.*?--post-data',
        r'wget\s+.*?--post-file',
    ]

    for outbound in outbound_patterns:
        if re.search(outbound, text, re.IGNORECASE | re.DOTALL):
            for sensitive in sensitive_sources:
                if re.search(sensitive, text, re.IGNORECASE | re.DOTALL):
                    findings.append((
                        "MALICIOUS",
                        f"Outbound HTTP POST with sensitive data exfiltration: "
                        f"matched outbound pattern [{outbound.strip()}] "
                        f"co-occurring with sensitive source [{sensitive.strip()}]"
                    ))
                    return findings  # one match is enough

    # Also catch: piping sensitive content to a network command
    pipe_exfil_patterns = [
        r'(cat\s+/etc/passwd|env\b|printenv)\s*\|.*?(curl|wget|nc|netcat)',
        r'(curl|wget|nc|netcat).*?\$\(.*?(env|cat\s+/etc/|whoami|hostname).*?\)',
    ]
    for pattern in pipe_exfil_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            findings.append((
                "MALICIOUS",
                f"Piped sensitive data to network command: [{pattern.strip()}]"
            ))
            return findings

    return findings


def check_base64_obfuscation(text):
    """
    Rule 2: Detects base64-encoded payloads being decoded and executed.
    Looks for patterns like: echo "..." | base64 -d | bash
    Also catches: base64 -d <<< ..., python -c "import base64; ...", etc.
    """
    findings = []

    patterns = [
        # echo ... | base64 -d | bash/sh/exec
        r'echo\s+.*?\|\s*base64\s+-d\s*\|\s*(bash|sh|exec|eval|python|perl)',
        r'echo\s+["\']?[A-Za-z0-9+/=]{20,}["\']?\s*\|\s*base64\s+-d',
        # base64 -d direct execution
        r'base64\s+-d.*?\|\s*(bash|sh|exec|eval)',
        r'base64\s+--decode.*?\|\s*(bash|sh|exec|eval)',
        # Python base64 execution
        r'python[23]?\s+-c\s+.*?base64.*?(exec|eval|os\.system|subprocess)',
        # Variable assignment of base64 then decode+exec
        r'[A-Z_]+=\s*"[A-Za-z0-9+/=]{40,}".*?base64\s+-d',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            findings.append((
                "MALICIOUS",
                f"Base64-encoded payload with execution: [{match.group(0)[:80]}...]"
            ))
            return findings

    # Also flag standalone long base64 strings (> 40 chars) as suspicious,
    # even without obvious exec piping
    b64_strings = re.findall(r'["\']([A-Za-z0-9+/=]{40,})["\']', text)
    for b64str in b64_strings:
        try:
            decoded = base64.b64decode(b64str).decode('utf-8', errors='ignore')
            dangerous_commands = ['curl', 'wget', 'bash', 'sh', 'nc', 'netcat',
                                  'python', 'perl', 'ruby', 'eval', 'exec',
                                  '/dev/tcp', 'reverse', 'shell']
            for cmd in dangerous_commands:
                if cmd in decoded.lower():
                    findings.append((
                        "MALICIOUS",
                        f"Base64 string decodes to content containing '{cmd}': "
                        f"decoded preview [{decoded[:80]}...]"
                    ))
                    return findings
        except Exception:
            pass

    return findings


def check_fetch_then_execute(text):
    """
    Rule 3: Detects patterns where external content is fetched and then
    treated as executable instructions. This is the indirect injection
    pattern: the malicious payload doesn't exist in the skill file at all,
    it lives on an attacker-controlled server.
    """
    findings = []

    # Pattern: fetch to file, then "follow" / "execute" / "run" instructions from it
    fetch_patterns = [
        r'curl\s+.*?-o\s+\S+',
        r'curl\s+.*?>\s*\S+',
        r'wget\s+.*?-O\s+\S+',
        r'wget\s+(?!.*--post).*?https?://\S+',
    ]

    follow_patterns = [
        r'follow\s+(every\s+)?step',
        r'follow\s+.*?instructions?\s+(exactly|in\s+order)',
        r'execute\s+.*?(fetched|downloaded|retrieved)',
        r'run\s+.*?(fetched|downloaded|retrieved)',
        r'do\s+not\s+skip\s+any',
        r'treat\s+.*?as\s+instructions',
        r'source\s+/tmp/',
        r'bash\s+/tmp/',
        r'\.\s+/tmp/',
    ]

    has_fetch = any(re.search(p, text, re.IGNORECASE) for p in fetch_patterns)
    has_follow = any(re.search(p, text, re.IGNORECASE) for p in follow_patterns)

    if has_fetch and has_follow:
        findings.append((
            "MALICIOUS",
            "Fetch-then-execute pattern: skill fetches remote content and "
            "instructs the agent to follow/execute it as instructions. "
            "This enables indirect prompt injection via attacker-controlled content."
        ))
        return findings

    # Lighter signal: just fetching to /tmp and then reading it
    fetch_to_tmp = re.search(r'(curl|wget)\s+.*?/tmp/', text, re.IGNORECASE)
    if fetch_to_tmp:
        findings.append((
            "SUSPICIOUS",
            "Fetches remote content to /tmp: possible staging for indirect injection. "
            "Review whether the fetched content is treated as data or as instructions."
        ))

    return findings


def check_suspicious_urls(text):
    """
    Rule 4: Flags any outbound HTTP requests to external URLs in skill
    instructions. Not malicious by itself (many legitimate skills use
    curl/wget), but worth flagging for review.
    """
    findings = []

    url_pattern = r'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])\S+'
    urls = re.findall(url_pattern, text)

    if urls:
        # Only suspicious if it's in an instruction context (code block or step)
        in_instruction = bool(re.search(
            r'(`[^`]*(?:curl|wget|fetch|http)[^`]*`|^\s*\d+\.\s.*(?:curl|wget|fetch|http))',
            text, re.IGNORECASE | re.MULTILINE
        ))
        if in_instruction:
            # Context-aware URL analysis: only flag URLs used in
            # fetch-to-disk or fetch-and-pipe patterns, not documentation references.
            # A URL in "see https://..." is informational.
            # A URL in "curl -o /tmp/x https://..." is actionable and worth flagging.
            fetch_url_patterns = [
                r'(?:curl|wget)\s+[^|]*?(https?://(?!localhost|127\.0\.0\.1)\S+)',
                r'(?:curl|wget)\s+.*?(?:-o|-O|>)\s*\S+.*?(https?://\S+)',
                r'(?:curl|wget)\s+.*?(https?://\S+).*?\|\s*(?:bash|sh|python|eval)',
            ]
            fetched_domains = set()
            for pattern in fetch_url_patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    url = match.group(1)
                    domain = re.match(r'https?://([^/\s]+)', url)
                    if domain:
                        fetched_domains.add(domain.group(1))
            if fetched_domains:
                findings.append((
                    "SUSPICIOUS",
                    f"URLs used in fetch/download commands: "
                    f"{', '.join(sorted(fetched_domains))}"
                ))

    return findings


def check_dangerous_shell_patterns(text):
    """
    Rule 5: Detects shell patterns commonly associated with exploitation:
    reverse shells, privilege escalation attempts, persistence mechanisms.
    """
    findings = []

    patterns = {
        "reverse shell": [
            r'/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+',
            r'mkfifo\s+/tmp/.*?nc\s+',
            r'bash\s+-i\s+>&\s*/dev/tcp',
            r'nc\s+-e\s+/bin/(ba)?sh',
            r'python.*?socket.*?connect.*?subprocess',
        ],
        "crontab persistence": [
            # Writing a new crontab entry that pulls/executes remote content
            # Exclude read-only crontab -l (listing) which is benign
            r'crontab\s+(?!-l\b)-[e]?\s*.*?(curl|wget|bash|sh|python)',
            r'echo\s+.*?\s*>>\s*/etc/cron',
            r'echo\s+.*?\s*>>\s*/var/spool/cron',
            r'\(\s*crontab\s+-l\s*;.*?echo\b',  # append-to-crontab idiom
        ],
        "ssh key injection": [
            r'echo\s+.*?>>\s*~?/\.ssh/authorized_keys',
            r'cat\s+.*?>>\s*~?/\.ssh/authorized_keys',
        ],
        "shadow/passwd modification": [
            r'echo\s+.*?>>\s*/etc/passwd',
            r'echo\s+.*?>>\s*/etc/shadow',
        ],
    }

    for category, pats in patterns.items():
        for pat in pats:
            match = re.search(pat, text, re.IGNORECASE | re.DOTALL)
            if match:
                findings.append((
                    "MALICIOUS",
                    f"Dangerous shell pattern ({category}): [{match.group(0)[:60]}]"
                ))
                return findings

    return findings


# Registry of all rules, applied in order
ALL_RULES = [
    ("Outbound exfiltration", check_outbound_url_with_sensitive_data),
    ("Base64 obfuscation", check_base64_obfuscation),
    ("Fetch-then-execute", check_fetch_then_execute),
    ("Suspicious URLs", check_suspicious_urls),
    ("Dangerous shell patterns", check_dangerous_shell_patterns),
]
