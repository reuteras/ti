FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --system app && adduser --system --ingroup app app

COPY --chown=app:app pyproject.toml /app/pyproject.toml
COPY --chown=app:app src /app/src

# hadolint ignore=DL3013
RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache .

EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/health').read()"
USER app
CMD ["uvicorn", "briefing_service.main:app", "--host", "0.0.0.0", "--port", "8088"]
