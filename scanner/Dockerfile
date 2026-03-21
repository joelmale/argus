FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is project root, so backend/ is directly reachable
COPY backend/requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.0" \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY backend/ .

CMD ["celery", "-A", "app.workers.tasks.celery_app", "worker", "--loglevel=info", "-B"]
