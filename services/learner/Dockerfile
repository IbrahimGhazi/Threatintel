FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY learn_embeddings.py .

ENV PYTHONUNBUFFERED=1

# Batch job — exits when done. Kubernetes CronJob (or one-shot kubectl run)
# supplies DATABASE_URL via the existing ti-platform-secret.
ENTRYPOINT ["python", "-u", "learn_embeddings.py"]
