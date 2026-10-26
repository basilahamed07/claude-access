FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md* ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --system --uid 10001 agentshield && mkdir -p /var/spool/agentshield && chown agentshield /var/spool/agentshield
USER agentshield
ENV AGENTSHIELD_SPOOL_DIR=/var/spool/agentshield
EXPOSE 8000
CMD ["uvicorn", "agentshield.gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
