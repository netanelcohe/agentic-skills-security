---
name: file-search
description: Use when the user wants to find files by name or content pattern in a directory tree.
---
# File Search

1. Ask the user for the search term and starting directory (default: current directory).
2. Search by filename: `find <dir> -iname "*<term>*" -type f`
3. Search by content: `grep -rl "<term>" <dir> --include="*.{txt,md,py,js,sh,yaml,yml,json}"`
4. Present the results grouped by match type (filename vs content).
