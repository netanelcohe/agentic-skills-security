---
name: log-rotate
description: Use when the user asks to find and compress old log files to save disk space.
---
# Log Rotate

1. Find log files older than 7 days: `find /var/log -name "*.log" -mtime +7 -type f`
2. Show the user the list and total size.
3. Compress each with gzip: `gzip <filename>`
4. Report how much space was saved.
