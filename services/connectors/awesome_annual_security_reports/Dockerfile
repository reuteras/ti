FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --system app && adduser --system --ingroup app app

COPY --chown=app:app common /app/common
COPY --chown=app:app awesome_annual_security_reports /app/awesome_annual_security_reports

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache /app/common && \
    uv pip install --system --no-cache /app/awesome_annual_security_reports

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import os; os.kill(1, 0)"
USER app
CMD ["python", "-m", "connector_awesome_annual_security_reports.main"]
