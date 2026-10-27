# syntax=docker/dockerfile:1
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_HTTP_TIMEOUT=120 UV_HTTP_RETRIES=10 UV_LINK_MODE=copy
# uv comes from the container registry (same path as the base image), not from PyPI, so the installer
# itself does not depend on the host that stalls. It downloads in parallel and retries on its own.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml README.md* ./
# Dependencies first: this layer is cached until pyproject.toml changes. The uv cache mount keeps every
# file already downloaded, so each retry (and any rebuild after a failure) resumes instead of starting over.
# Optional PyPI mirror for a bad connection, passed as a BuildKit secret so it never lands in the image or
# its history: docker build --secret id=pip_index_url,env=PIP_INDEX_URL ...
RUN --mount=type=cache,target=/root/.cache/uv --mount=type=secret,id=pip_index_url,required=false \
    set -e; \
    [ ! -s /run/secrets/pip_index_url ] || export UV_INDEX_URL="$(cat /run/secrets/pip_index_url)"; \
    python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/requirements.txt; \
    for i in 1 2 3 4 5; do \
      uv pip install --system -r /tmp/requirements.txt && exit 0; \
      echo "dependency install failed (attempt $i of 5), retrying" >&2; sleep 5; \
    done; exit 1
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv --mount=type=secret,id=pip_index_url,required=false \
    set -e; \
    [ ! -s /run/secrets/pip_index_url ] || export UV_INDEX_URL="$(cat /run/secrets/pip_index_url)"; \
    for i in 1 2 3 4 5; do \
      uv pip install --system --no-deps . && exit 0; \
      echo "project install failed (attempt $i of 5), retrying" >&2; sleep 5; \
    done; exit 1
RUN useradd --system --uid 10001 agentshield && mkdir -p /var/spool/agentshield && chown agentshield /var/spool/agentshield
USER agentshield
ENV AGENTSHIELD_SPOOL_DIR=/var/spool/agentshield
EXPOSE 8000
CMD ["uvicorn", "agentshield.gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
