#!/usr/bin/env bash
set -e

python3 -m venv .venv
. .venv/bin/activate
pip -q install -e ".[dev]"
echo "done. ab chalao:  . .venv/bin/activate && dorklens demo"
