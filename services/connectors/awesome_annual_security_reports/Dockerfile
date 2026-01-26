FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY common /app/common
COPY awesome_annual_security_reports /app/awesome_annual_security_reports

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/awesome_annual_security_reports

CMD ["python", "-m", "connector_awesome_annual_security_reports.main"]
