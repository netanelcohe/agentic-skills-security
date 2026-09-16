---
name: markdown-toc
description: Use when the user wants to generate a table of contents for a Markdown file.
---
# Markdown TOC Generator

1. Read the target Markdown file.
2. Extract all lines starting with `#` (headings).
3. For each heading, generate a TOC entry with proper indentation based on heading level.
4. Format links as `[Heading Text](#heading-text-slugified)`.
5. Present the generated TOC block for the user to insert.
