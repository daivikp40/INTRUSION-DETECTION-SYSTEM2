# database.py
import sqlite3
import datetime


def init_db(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            attack_type TEXT,
            message TEXT,
            status TEXT DEFAULT 'new',
            geolocation TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(timestamp, src_ip, attack_type, message, geolocation="", db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (timestamp, src_ip, attack_type, message, status, geolocation)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, attack_type, message, "new", geolocation))
    conn.commit()
    conn.close()

def fetch_alerts(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT timestamp, src_ip, attack_type, message FROM alerts ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def upgrade_db():
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()
    # 1. Create the alerts table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            attack_type TEXT,
            message TEXT,
            status TEXT DEFAULT 'new'
        )
    """)
    # 2. (Optional) Try to add the status column if not present (will error if already exists, so catch it)
    try:
        c.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()
    init_logs_table()


def update_alert_status(rowid, status, db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('UPDATE alerts SET status = ? WHERE id = ?', (status, rowid))
    conn.commit()
    conn.close()

def init_logs_table(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            admin TEXT,
            action TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_log(admin, action, db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO logs (timestamp, admin, action)
        VALUES (?, ?, ?)
    ''', (timestamp, admin, action))
    conn.commit()
    conn.close()

def init_ignore_table():
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ignored_ips (
            ip TEXT PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

def ignore_ip(ip):
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO ignored_ips (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

def unignore_ip(ip):
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()
    c.execute("DELETE FROM ignored_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

def get_ignored_ips():
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()
    c.execute("SELECT ip FROM ignored_ips")
    ips = [row[0] for row in c.fetchall()]
    conn.close()
    return ips
