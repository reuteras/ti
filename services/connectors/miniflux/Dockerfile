FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY common /app/common
COPY miniflux /app/miniflux

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/miniflux

CMD ["python", "-m", "connector_miniflux.main"]
