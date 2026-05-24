FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget netcat-openbsd iproute2 iputils-ping \
    net-tools arp-scan tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY attacks/ ./attacks/
COPY entrypoint.py .

CMD ["python", "entrypoint.py"]
