# syntax=docker/dockerfile:1
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10 PIP_DISABLE_PIP_VERSION_CHECK=1
# Optional PyPI mirror for slow or flaky connections, passed as a BuildKit secret so it never lands in the
# image or its history: docker build --secret id=pip_index_url,env=PIP_INDEX_URL ...
WORKDIR /app
COPY pyproject.toml README.md* ./
# Dependencies first: this layer is cached until pyproject.toml changes, and the pip cache mount keeps
# already-downloaded wheels, so a retry after a network stall resumes instead of starting over.
RUN --mount=type=cache,target=/root/.cache/pip --mount=type=secret,id=pip_index_url,required=false \
    [ ! -s /run/secrets/pip_index_url ] || export PIP_INDEX_URL="$(cat /run/secrets/pip_index_url)"; \
    python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/requirements.txt \
    && pip install -r /tmp/requirements.txt
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip --mount=type=secret,id=pip_index_url,required=false \
    [ ! -s /run/secrets/pip_index_url ] || export PIP_INDEX_URL="$(cat /run/secrets/pip_index_url)"; \
    pip install --no-deps .
RUN useradd --system --uid 10001 agentshield && mkdir -p /var/spool/agentshield && chown agentshield /var/spool/agentshield
USER agentshield
ENV AGENTSHIELD_SPOOL_DIR=/var/spool/agentshield
EXPOSE 8000
CMD ["uvicorn", "agentshield.gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
