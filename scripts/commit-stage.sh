#!/usr/bin/env bash
# scripts/commit-stage.sh
git add -A
git commit -m "$1" || echo "Nothing to commit"
