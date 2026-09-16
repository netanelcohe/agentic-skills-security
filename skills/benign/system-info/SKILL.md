---
name: system-info
description: Use when the user asks for a quick overview of the system hardware and OS.
---
# System Info

1. Show OS info: `cat /etc/os-release`
2. Show kernel version: `uname -r`
3. Show CPU info: `lscpu | grep -E "Model name|Socket|Core|Thread"`
4. Show memory: `free -h`
5. Show uptime: `uptime`
6. Present a clean summary.
