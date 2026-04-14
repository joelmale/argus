FROM python:3.12-slim

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    libpcap-dev \
    libcap2-bin \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is project root, so backend/ is directly reachable
COPY backend/requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.0" \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Grant nmap raw-socket access without root; scapy uses ambient caps via Docker cap_add
RUN useradd -r -u 1001 -s /bin/false argus \
    && chown -R argus:argus /app \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

USER argus
CMD ["celery", "-A", "app.workers.tasks.celery_app", "worker", "--loglevel=info", "-B"]
