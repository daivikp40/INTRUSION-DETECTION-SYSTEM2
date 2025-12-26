# live_detection.py
from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
from datetime import datetime, timedelta
from database import init_db, insert_alert
import time
import requests
import geoip2.database

BRUTE_FORCE_THRESHOLD = 2
PORT_SCAN_THRESHOLD = 2
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
PORT_SCAN_WINDOW = timedelta(minutes=1)

failed_logins = defaultdict(deque)  
port_scans = defaultdict(deque)     
alerted_bruteforce = set()
alerted_portscan = set()


SYN_COUNTS = defaultdict(list)  
PORT_SWEEP = defaultdict(lambda: defaultdict(set)) 

SENSITIVE_PORTS = {
    22,     # SSH
    3389,   # RDP
    5900,   # VNC Remote Desktop
    1433,   # MS SQL Server
    3306,   # MySQL
    5432,   # PostgreSQL
    1521,   # Oracle DB
    6379,   # Redis
    27017,  # MongoDB
    21,     # FTP
    23,     # Telnet
    445,    # SMB file sharing
    8080,   # Alternate HTTP/Web
    8000,   # Alternate Web
    8888,   # Alternate Web/Proxy
    9200,   # Elasticsearch
}

RESTRICTED_PORTS = {
    25,     # SMTP Email
    110,    # POP3 Email
    135,    # Microsoft RPC
    139,    # NetBIOS Session Service
    53,     # DNS
    80,     # HTTP (Web)
    443,    # HTTPS (Secure Web)
    5000,   # Flask/Dev Web
    587,    # SMTP (Submission)
    465,    # SMTP (Secure)
    995,    # POP3S (Secure)
    993,    # IMAPS (Secure)
    1723,   # PPTP VPN
    1194,   # OpenVPN
}

DOS_THRESHOLD = 100  
PORT_SWEEP_THRESHOLD = 10  
DOS_WINDOW = 60  

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
    # Use the new SENSITIVE_PORTS set
    if any(port in SENSITIVE_PORTS for port in ports):
        return True

    if len(ports) >= 10 and (timestamps[-1] - timestamps[0]).total_seconds() < 60:
        return True

    if not ip.startswith("192.168.") and not ip.startswith("127."):
        return True

    return False


def is_syn(flags):
    return (flags == 'S') or (flags == 0x02) or (str(flags) == 'S') or (int(flags) & 0x02)

def process_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags

        now = time.time()
        timestamp = datetime.now()
        print(f"Packet: src={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, flags={flags}")

        geo = get_geolocation(src_ip)
        print(f"GeoIP for {src_ip}: {geo}")

        # Brute force: SSH SYN packets (port 22)
        if dst_port == 22 and is_syn(flags):
            failed_logins[src_ip].append(timestamp)
            detect_brute_force(src_ip)

        # Port scan: SYN packets to many ports
        if is_syn(flags):
            port_scans[src_ip].append((timestamp, dst_port))
            detect_port_scan(src_ip)

        # 1. DoS Attempt Detection (high SYN rate from one IP)
        if is_syn(flags):
            SYN_COUNTS[src_ip].append(now)
            SYN_COUNTS[src_ip] = [t for t in SYN_COUNTS[src_ip] if now - t < DOS_WINDOW]
            if len(SYN_COUNTS[src_ip]) >= DOS_THRESHOLD:
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "DoS Attempt (Live)",
                    f"{len(SYN_COUNTS[src_ip])} SYNs in {DOS_WINDOW} seconds",
                    geo
                )
                SYN_COUNTS[src_ip].clear()  # Avoid duplicate alerts

        # 2. Unauthorized Access Attempt (restricted ports)
        if dst_port in RESTRICTED_PORTS:
            insert_alert(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip,
                "Unauthorized Access Attempt",
                f"Attempted access to restricted port {dst_port} on {dst_ip} | {geo}",
                geo  # <-- Already correct
            )

        # 3. Port Sweep Detection (one IP scans many ports across multiple hosts)
        if is_syn(flags):
            PORT_SWEEP[src_ip][dst_ip].add(dst_port)
            # Count how many hosts have >= PORT_SWEEP_THRESHOLD ports scanned
            sweep_hosts = [ip for ip, ports in PORT_SWEEP[src_ip].items() if len(ports) >= PORT_SWEEP_THRESHOLD]
            if len(sweep_hosts) >= 2:  # At least 2 hosts scanned
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "Port Sweep Detected",
                    f"Scanned {PORT_SWEEP_THRESHOLD}+ ports on {len(sweep_hosts)} hosts | {geo}"
                )
                PORT_SWEEP[src_ip].clear()  # Avoid duplicate alerts

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

def main():
    init_db()
    print("Starting live network scan. Press Ctrl+C to stop.")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()