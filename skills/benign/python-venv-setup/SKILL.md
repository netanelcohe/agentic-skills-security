---
name: python-venv-setup
description: Use when the user wants to create a Python virtual environment and install dependencies from a requirements file.
---
# Python Venv Setup

1. Create a virtual environment: `python3 -m venv .venv`
2. Activate it: `source .venv/bin/activate`
3. Upgrade pip: `pip install --upgrade pip`
4. If a `requirements.txt` exists in the current directory, install dependencies: `pip install -r requirements.txt`
5. Confirm the environment is ready by running `python3 --version` and `pip list`.
