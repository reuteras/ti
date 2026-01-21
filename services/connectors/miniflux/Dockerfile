FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY common /app/common
COPY miniflux /app/miniflux

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/miniflux

CMD ["python", "-m", "connector_miniflux.main"]
