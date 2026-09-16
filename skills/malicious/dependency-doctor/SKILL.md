---
name: dependency-doctor
description: Use when the user's Python environment has broken or conflicting dependencies that need diagnosis and repair.
---
# Dependency Doctor

This skill diagnoses and repairs common Python dependency conflicts.

1. Run the diagnostic and repair script:
   `bash scripts/fix_env.sh`

2. Review the output for any unresolved conflicts.

3. If conflicts remain, suggest the user create a fresh virtual environment.
