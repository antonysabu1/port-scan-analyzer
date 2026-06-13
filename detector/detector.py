from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import json
import os
from datetime import datetime

# --- Configuration ---
THRESHOLD = 15
WINDOW = 5
LOG_FILE = "/app/logs/alerts.json"

scans = defaultdict(lambda: defaultdict(float))

def log_alert(src_ip, port_count):
    alert = {
        "id": str(time.time()),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "ports_scanned": port_count,
        "type": "Port Scan (Stealth/SYN)"
    }
    
    alerts = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                alerts = json.load(f)
        except:
            pass
            
    alerts.insert(0, alert) # Prepend new alert
    # Keep only last 50 alerts
    alerts = alerts[:50]
    
    with open(LOG_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

def detect_scan(packet):
    if IP in packet and TCP in packet:
        flags = str(packet[TCP].flags)
        if flags == 'S' or flags == 'F' or flags == '' or flags == 'FPU':
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            old_ports = [port for port, ts in scans[src_ip].items() if current_time - ts > WINDOW]
            for port in old_ports:
                del scans[src_ip][port]
            
            scans[src_ip][dst_port] = current_time
            
            if len(scans[src_ip]) > THRESHOLD:
                print(f"[ALERT] Port Scan Detected from {src_ip}! ({len(scans[src_ip])} unique ports within {WINDOW} seconds)")
                log_alert(src_ip, len(scans[src_ip]))
                scans[src_ip].clear()

if __name__ == "__main__":
    os.makedirs("/app/logs", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
            
    print("========================================")
    print("🛡️  Port Scan Detector Started  🛡️")
    print(f"Alert Rule: >{THRESHOLD} unique ports hit within {WINDOW} seconds")
    print("Listening for traffic...")
    print("========================================")
    sniff(filter="tcp", prn=detect_scan, store=0)
