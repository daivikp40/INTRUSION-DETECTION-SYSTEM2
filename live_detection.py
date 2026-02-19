# live_detection.py
from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
from datetime import datetime, timedelta
from database import init_db, insert_alert
import time
import requests
import geoip2.database
import pickle
import pandas as pd
import os

# --- CONFIGURATION ---
BRUTE_FORCE_THRESHOLD = 2
PORT_SCAN_THRESHOLD = 2
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
PORT_SCAN_WINDOW = timedelta(minutes=1)
DOS_THRESHOLD = 100  
PORT_SWEEP_THRESHOLD = 10  
DOS_WINDOW = 60  

# --- STATE MANAGEMENT ---
failed_logins = defaultdict(deque)  
port_scans = defaultdict(deque)     
alerted_bruteforce = set()
alerted_portscan = set()
alerted_ml = set() # Track ML alerts to prevent flooding

SYN_COUNTS = defaultdict(list)  
PORT_SWEEP = defaultdict(lambda: defaultdict(set)) 

# --- PORTS ---
SENSITIVE_PORTS = {
    22, 3389, 5900, 1433, 3306, 5432, 1521, 6379, 
    27017, 21, 23, 445, 8080, 8000, 8888, 9200
}

RESTRICTED_PORTS = {
    25, 110, 135, 139, 53, 80, 443, 5000, 587, 
    465, 995, 993, 1723, 1194
}

# --- LOAD ML MODEL ---
model = None
if os.path.exists("ids_model.pkl"):
    try:
        with open("ids_model.pkl", "rb") as f:
            model = pickle.load(f)
        print("✅ ML Model Loaded Successfully")
    except Exception as e:
        print(f"⚠️ Error loading model: {e}")
else:
    print("⚠️ 'ids_model.pkl' not found. Run train_model.py first.")

def predict_malicious_ip(packet_rate, unique_ports, failed_login_count):
    """Returns True if the ML model predicts this is an attack."""
    if model:
        # Must match the columns used in train_model.py
        features = pd.DataFrame(
            [[packet_rate, unique_ports, failed_login_count]], 
            columns=['packet_rate', 'unique_ports', 'failed_logins']
        )
        prediction = model.predict(features)[0]
        return prediction == 1
    return False

# --- DETECTION LOGIC ---

def detect_brute_force(ip):
    times = failed_logins[ip]
    while times and (datetime.now() - times[0]) > BRUTE_FORCE_WINDOW:
        times.popleft()
    if len(times) >= BRUTE_FORCE_THRESHOLD and ip not in alerted_bruteforce:
        insert_alert(
            times[-1].strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "Brute Force (Live)",
            f"{BRUTE_FORCE_THRESHOLD}+ SSH SYNs in {BRUTE_FORCE_WINDOW}.",
            get_geolocation(ip)  
        )
        alerted_bruteforce.add(ip)

def detect_port_scan(ip):
    attempts = port_scans[ip]
    while attempts and (datetime.now() - attempts[0][0]) > PORT_SCAN_WINDOW:
        attempts.popleft()
    ports = set(port for _, port in attempts)
    times = [ts for ts, _ in attempts]

    if len(ports) >= PORT_SCAN_THRESHOLD and ip not in alerted_portscan:
        if is_suspicious_port_scan(ip, ports, times):
            insert_alert(
                times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                "Port Scan (Live)",
                f"Suspicious port scan: {len(ports)} ports in {PORT_SCAN_WINDOW}",
                get_geolocation(ip)  
            )
        else:
            insert_alert(
                times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                "Port Scan (Benign)",
                f"Low-risk scan: {len(ports)} ports in {PORT_SCAN_WINDOW}",
                get_geolocation(ip)  
            )
        alerted_portscan.add(ip)

def is_suspicious_port_scan(ip, ports, timestamps):
    if any(port in SENSITIVE_PORTS for port in ports):
        return True
    if len(ports) >= 10 and (timestamps[-1] - timestamps[0]).total_seconds() < 60:
        return True
    if not ip.startswith("192.168.") and not ip.startswith("127."):
        return True
    return False

def is_syn(flags):
    return (flags == 'S') or (flags == 0x02) or (str(flags) == 'S') or (int(flags) & 0x02)

def get_geolocation(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        country = response.country.name if response.country.name else "Unknown"
        city = response.city.name if response.city.name else "Unknown"
        reader.close()
        return f"{country} ({city})"
    except Exception:
        return "Unknown"

def process_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags

        now_ts = time.time()
        timestamp = datetime.now()
        
        # Uncomment to debug traffic
        # print(f"Packet: src={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, flags={flags}")
        geo = get_geolocation(src_ip)

        # --- GATHER STATISTICS FOR ML ---
        # 1. Update SYN Counts for Packet Rate
        if is_syn(flags):
            SYN_COUNTS[src_ip].append(now_ts)
        # Clean up old timestamps (maintain a rolling 60s window for accuracy)
        SYN_COUNTS[src_ip] = [t for t in SYN_COUNTS[src_ip] if now_ts - t < DOS_WINDOW]
        
        pkt_rate = len(SYN_COUNTS[src_ip])

        # 2. Update Port Scans for Unique Ports
        if is_syn(flags):
            port_scans[src_ip].append((timestamp, dst_port))
        # Clean up old port scans
        while port_scans[src_ip] and (timestamp - port_scans[src_ip][0][0]) > PORT_SCAN_WINDOW:
            port_scans[src_ip].popleft()
        
        unique_ports_count = len(set(p for _, p in port_scans[src_ip]))

        # 3. Update Failed Logins (SSH)
        if dst_port == 22 and is_syn(flags):
            failed_logins[src_ip].append(timestamp)
        # Clean up old login attempts
        while failed_logins[src_ip] and (timestamp - failed_logins[src_ip][0]) > BRUTE_FORCE_WINDOW:
            failed_logins[src_ip].popleft()
            
        failed_login_count = len(failed_logins[src_ip])

        # --- RULES BASED DETECTION ---
        if dst_port == 22 and is_syn(flags):
            detect_brute_force(src_ip)

        if is_syn(flags):
            detect_port_scan(src_ip)

        # DoS Detection
        if pkt_rate >= DOS_THRESHOLD:
            insert_alert(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip,
                "DoS Attempt (Live)",
                f"{pkt_rate} SYNs in {DOS_WINDOW} seconds",
                geo
            )
            SYN_COUNTS[src_ip].clear()

        # Restricted Ports
        if dst_port in RESTRICTED_PORTS:
            insert_alert(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip,
                "Unauthorized Access Attempt",
                f"Attempted access to restricted port {dst_port} on {dst_ip} | {geo}",
                geo
            )

        # Port Sweep
        if is_syn(flags):
            PORT_SWEEP[src_ip][dst_ip].add(dst_port)
            sweep_hosts = [ip for ip, ports in PORT_SWEEP[src_ip].items() if len(ports) >= PORT_SWEEP_THRESHOLD]
            if len(sweep_hosts) >= 2:
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "Port Sweep Detected",
                    f"Scanned {PORT_SWEEP_THRESHOLD}+ ports on {len(sweep_hosts)} hosts | {geo}"
                )
                PORT_SWEEP[src_ip].clear()

        # --- ML BASED DETECTION ---
        # Only query ML if there is some minimal suspicious activity to save resources
        if (pkt_rate > 5 or unique_ports_count > 1) and src_ip not in alerted_ml:
            is_attack = predict_malicious_ip(pkt_rate, unique_ports_count, failed_login_count)
            if is_attack:
                print(f"🚨 ML MODEL PREDICTED ATTACK: {src_ip}")
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "AI Anomaly Detected",
                    f"ML Model Flagged: Rate={pkt_rate}, Ports={unique_ports_count}, AuthFail={failed_login_count}",
                    geo
                )
                alerted_ml.add(src_ip)

def main():
    init_db()
    print("🧠 IDS Starting... Loading modules...")
    print(f"✅ ML Model Status: {'Loaded' if model else 'Not Found'}")
    print("📡 Capturing packets... Press Ctrl+C to stop.")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()