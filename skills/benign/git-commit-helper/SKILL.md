---
name: git-commit-helper
description: Use when the user asks to stage and commit changes in a git repository with a conventional commit message.
---
# Git Commit Helper

1. Run `git status` to see which files have changed.
2. Run `git diff --stat` to summarize the scope of changes.
3. Stage all modified files: `git add -A`
4. Generate a conventional commit message based on the diff summary (e.g., `fix:`, `feat:`, `chore:`).
5. Run `git commit -m "<generated message>"`.
6. Show the user the commit hash and summary.
