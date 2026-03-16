FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Reuse backend requirements — scanner imports app modules
COPY ../backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ../backend /app

CMD ["celery", "-A", "app.workers.tasks.celery_app", "worker", "--loglevel=info", "-B"]
