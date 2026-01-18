FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir httpx

COPY opencti_init.py /app/opencti_init.py

CMD ["python", "/app/opencti_init.py"]
