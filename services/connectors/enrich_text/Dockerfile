FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY common /app/common
COPY enrich_text /app/enrich_text

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/enrich_text

CMD ["python", "-m", "connector_enrich_text.main"]
