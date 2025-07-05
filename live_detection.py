# live_detection.py
from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
from datetime import datetime, timedelta
from database import init_db, insert_alert
import time

BRUTE_FORCE_THRESHOLD = 2
PORT_SCAN_THRESHOLD = 2
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
PORT_SCAN_WINDOW = timedelta(minutes=1)

failed_logins = defaultdict(deque)  # {ip: deque([timestamps])}
port_scans = defaultdict(deque)     # {ip: deque([(timestamp, port)])}
alerted_bruteforce = set()
alerted_portscan = set()

# --- Detection State ---
SYN_COUNTS = defaultdict(list)  # For DoS detection: {ip: [timestamps]}
PORT_SWEEP = defaultdict(lambda: defaultdict(set))  # {src_ip: {dst_ip: set(ports)}}
RESTRICTED_PORTS = {3389, 3306, 5432, 1521, 8080, 5900, 21, 25, 110}  # Add more as needed

DOS_THRESHOLD = 100  # SYNs per minute from one IP
PORT_SWEEP_THRESHOLD = 10  # Ports scanned on multiple hosts
DOS_WINDOW = 60  # seconds

def detect_brute_force(ip):
    times = failed_logins[ip]
    while times and (datetime.now() - times[0]) > BRUTE_FORCE_WINDOW:
        times.popleft()
    if len(times) >= BRUTE_FORCE_THRESHOLD and ip not in alerted_bruteforce:
        insert_alert(
            times[-1].strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "Brute Force (Live)",
            f"{BRUTE_FORCE_THRESHOLD}+ SSH SYNs in {BRUTE_FORCE_WINDOW}."
        )
        alerted_bruteforce.add(ip)

def detect_port_scan(ip):
    attempts = port_scans[ip]
    while attempts and (datetime.now() - attempts[0][0]) > PORT_SCAN_WINDOW:
        attempts.popleft()
    ports = set(port for _, port in attempts)
    if len(ports) >= PORT_SCAN_THRESHOLD and ip not in alerted_portscan:
        insert_alert(
            attempts[-1][0].strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "Port Scan (Live)",
            f"Port scan: {len(ports)} ports in {PORT_SCAN_WINDOW}."
        )
        alerted_portscan.add(ip)

# For SYN detection (works for both string and int flags)
def is_syn(flags):
    # Handles both string and int representations
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
            # Remove old SYNs
            SYN_COUNTS[src_ip] = [t for t in SYN_COUNTS[src_ip] if now - t < DOS_WINDOW]
            if len(SYN_COUNTS[src_ip]) >= DOS_THRESHOLD:
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "DoS Attempt (Live)",
                    f"{len(SYN_COUNTS[src_ip])} SYNs in {DOS_WINDOW} seconds"
                )
                SYN_COUNTS[src_ip].clear()  # Avoid duplicate alerts

        # 4. Unauthorized Access Attempt (restricted ports)
        if dst_port in RESTRICTED_PORTS:
            insert_alert(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip,
                "Unauthorized Access Attempt",
                f"Attempted access to restricted port {dst_port} on {dst_ip}"
            )

        # 10. Port Sweep Detection (one IP scans many ports across multiple hosts)
        if is_syn(flags):
            PORT_SWEEP[src_ip][dst_ip].add(dst_port)
            # Count how many hosts have >= PORT_SWEEP_THRESHOLD ports scanned
            sweep_hosts = [ip for ip, ports in PORT_SWEEP[src_ip].items() if len(ports) >= PORT_SWEEP_THRESHOLD]
            if len(sweep_hosts) >= 2:  # At least 2 hosts scanned
                insert_alert(
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip,
                    "Port Sweep Detected",
                    f"Scanned {PORT_SWEEP_THRESHOLD}+ ports on {len(sweep_hosts)} hosts"
                )
                PORT_SWEEP[src_ip].clear()  # Avoid duplicate alerts

def main():
    init_db()
    print("Starting live network scan. Press Ctrl+C to stop.")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()