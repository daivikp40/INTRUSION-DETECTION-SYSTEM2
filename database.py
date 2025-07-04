# database.py
import sqlite3

def init_db(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            attack_type TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(timestamp, src_ip, attack_type, message, db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (timestamp, src_ip, attack_type, message, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, attack_type, message, "new"))
    conn.commit()
    conn.close()

def fetch_alerts(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT timestamp, src_ip, attack_type, message FROM alerts ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def upgrade_db(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    # Add status column if it doesn't exist
    c.execute("PRAGMA table_info(alerts)")
    columns = [col[1] for col in c.fetchall()]
    if "status" not in columns:
        c.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'")
    conn.commit()
    conn.close()

def update_alert_status(rowid, status, db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('UPDATE alerts SET status = ? WHERE id = ?', (status, rowid))
    conn.commit()
    conn.close()