FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

COPY common /app/common
COPY readwise /app/readwise

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/readwise

CMD ["python", "-m", "connector_readwise.main"]
