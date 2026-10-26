#!/usr/bin/env bash
# Run the test-suite against local throwaway services.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/dev-services.sh >/dev/null
export AGENTSHIELD_TEST_DSN=${AGENTSHIELD_TEST_DSN:-postgresql://postgres@localhost:5433/postgres}
export AGENTSHIELD_TEST_REDIS=${AGENTSHIELD_TEST_REDIS:-redis://localhost:6380/0}
exec .venv/bin/python -m pytest "$@"
