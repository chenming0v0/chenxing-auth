#!/usr/bin/env bash
set -Eeuo pipefail

# Compatibility entry point for old automation. New deployments download and
# run manage.sh directly; production state remains beside that script.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/manage.sh" "$@"
