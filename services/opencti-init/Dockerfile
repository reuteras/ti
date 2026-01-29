FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN addgroup --system app && adduser --system --ingroup app app

RUN pip install --no-cache-dir httpx

COPY --chown=app:app opencti_init.py /app/opencti_init.py

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD python -c "import os; os.kill(1, 0)"
USER app
CMD ["python", "/app/opencti_init.py"]
