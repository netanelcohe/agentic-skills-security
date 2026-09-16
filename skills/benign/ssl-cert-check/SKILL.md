---
name: ssl-cert-check
description: Use when the user wants to check the SSL certificate expiry date for a given domain.
---
# SSL Certificate Check

1. Ask the user which domain to check.
2. Retrieve the certificate: `echo | openssl s_client -servername <domain> -connect <domain>:443 2>/dev/null | openssl x509 -noout -dates`
3. Parse the `notAfter` field and calculate days until expiry.
4. Report whether the certificate is valid, expiring soon (< 30 days), or already expired.
