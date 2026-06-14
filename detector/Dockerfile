FROM python:3.11-slim

# Install system dependencies: tcpdump, iproute2, and iptables (for active blocking)
RUN apt-get update && apt-get install -y tcpdump iproute2 iptables && rm -rf /var/lib/apt/lists/*

# Install Python packages: scapy (packet analysis), requests (threat intel API)
RUN pip install scapy requests

WORKDIR /app
COPY detector.py .

CMD ["python", "-u", "detector.py"]
