FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache .

EXPOSE 8088
CMD ["uvicorn", "briefing_service.main:app", "--host", "0.0.0.0", "--port", "8088"]
