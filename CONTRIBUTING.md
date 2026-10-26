# Contributing

## Set up
```bash
cd agentshield && python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cd ../dashboard && npm ci
agentshield/scripts/dev-services.sh      # throwaway Postgres (5433) and Redis (6380)
```

## Run the checks (all of them run in CI)
| What | Command |
|---|---|
| Backend tests, lint, types | `cd agentshield && ./scripts/test.sh -q && .venv/bin/ruff check src tests && .venv/bin/mypy` |
| API contract | `cd agentshield && .venv/bin/python scripts/export_openapi.py --check` (regenerate with no flag, then `npm run gen:api` in `dashboard/`) |
| Fuzzing | `cd agentshield && ./scripts/schemathesis.sh` |
| Dashboard | `cd dashboard && npm run lint && npm run typecheck && npm test -- --run` |
| Browser tests and accessibility | `cd dashboard && npx playwright test` (starts a real stack) |
| SDK | `agentshield/.venv/bin/python -m pytest sdk/python -c sdk/python/pyproject.toml` |
| Eval | `agentshield/.venv/bin/python -m pytest eval -c eval/pytest.ini` |
| Demo end to end | `agentshield/.venv/bin/python -m pytest demo -c demo/pytest.ini` |
| README numbers | `agentshield/.venv/bin/python scripts/render_readme.py --check` |

## House rules
- Test first. A bug fix starts with a test that fails for the right reason.
- Every detection rule carries `examples` (positive and negative); the test suite runs them.
- Rule or threshold changes are tuned on the **dev** split of `eval/`; do not tune on **test**. If you must, say so in the commit and the results table.
- Any number in the README comes from `eval/results/` or `docs/measured/` through `scripts/render_readme.py`. Do not type numbers into `README.template.md`.
- The UI keeps the design rules in `dashboard/DESIGN_NOTES.md`: orange means stopped, mono is for literal values, every status has an icon and a word.
- Licence: Apache-2.0. By contributing you agree your work is released under it.
