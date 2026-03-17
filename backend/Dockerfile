FROM python:3.12-slim AS base

# Install system deps: nmap, arp-scan, net tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    net-tools \
    iputils-ping \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS dev

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["sh", "-c", "python scripts/migrate.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM base AS runtime

COPY . .

CMD ["sh", "-c", "python scripts/migrate.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
