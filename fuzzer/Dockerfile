FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump \
      iproute2 \
      iputils-ping \
      net-tools \
      tshark && \
    pip install --no-cache-dir scapy && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY fuzz_rtmp.py /app/fuzz_rtmp.py
