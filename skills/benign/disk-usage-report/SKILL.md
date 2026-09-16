---
name: disk-usage-report
description: Use when the user asks for a summary of disk usage on the system.
---
# Disk Usage Report

1. Show filesystem usage: `df -h`
2. Find the top 10 largest directories under /home: `du -sh /home/*/ 2>/dev/null | sort -rh | head -10`
3. Present the results in a readable summary.
