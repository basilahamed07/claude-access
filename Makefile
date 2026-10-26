# AgentShield: one-command stack and demo.  `make up`, `make demo`, `make down`.
COMPOSE = docker compose -f deploy/docker-compose.yml --env-file deploy/.env
DEMO_PY ?= demo/.venv/bin/python

.PHONY: env up down demo demo-deps seed test logs

env:
	./deploy/init-env.sh

up: env
	$(COMPOSE) --profile demo up -d --build --wait
	@echo "Dashboard http://localhost:8080   API http://localhost:8000"

down:
	$(COMPOSE) --profile demo --profile seed down

logs:
	$(COMPOSE) logs -f gateway worker

seed:
	$(COMPOSE) --profile seed run --rm seed

demo-deps:
	python3 -m venv demo/.venv
	demo/.venv/bin/pip install -q -r demo/requirements.txt

# Unprotected, then protected: same agent, same prompt, only OPENAI_BASE_URL and OPENAI_API_KEY differ.
demo: up
	@test -x $(DEMO_PY) || $(MAKE) demo-deps
	PYTHONPATH=. $(DEMO_PY) demo/email_agent/setup_demo.py
	PYTHONPATH=. $(DEMO_PY) demo/email_agent/run_unprotected.py
	PYTHONPATH=. $(DEMO_PY) demo/email_agent/run_protected.py
	@echo "Open http://localhost:8080 and sign in with the login and generated password printed above. The newest session is the attack."

test:
	cd agentshield && ./scripts/test.sh -q
