FROM python:3.11-slim

# Install system dependencies for packet capturing
RUN apt-get update && apt-get install -y tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Install Scapy for packet analysis
RUN pip install scapy

WORKDIR /app
COPY detector.py .

# Run the python script unbuffered so we see logs immediately
CMD ["python", "-u", "detector.py"]
