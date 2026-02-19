# streamlit_app.py
import streamlit as st
import pandas as pd
import sqlite3
import datetime
import time
import random
import io
from streamlit_autorefresh import st_autorefresh

# Database functions
from database import (
    update_alert_status,
    upgrade_db,
    insert_log,
    init_logs_table,
    init_ignore_table,
    ignore_ip,
    unignore_ip,
    get_ignored_ips,
    insert_alert
)

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="CyberGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- INITIALIZATION ---
init_ignore_table()
init_logs_table()
upgrade_db()

# --- CONSTANTS ---
CREDENTIALS = {"admin": "ids123", "analyst": "ids123"}

# --- HELPER FUNCTIONS ---
def get_connection():
    return sqlite3.connect("alerts.db", timeout=15)

def get_data():
    conn = get_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
    except:
        df = pd.DataFrame()
    conn.close()
    return df

def get_logs():
    conn = get_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
    except:
        df = pd.DataFrame()
    conn.close()
    return df

def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

def clear_all_data():
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM alerts")
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

def simulate_attack():
    """Generates basic fake attack data"""
    attack_types = ["Brute Force (Live)", "DoS Attempt (Live)", "Port Scan (Live)", "AI Anomaly Detected"]
    ips = [f"192.168.1.{random.randint(10, 255)}", f"10.0.0.{random.randint(5, 100)}", f"45.33.22.{random.randint(1, 99)}"]
    geos = ["United States (New York)", "China (Beijing)", "Russia (Moscow)", "Germany (Berlin)", "Unknown"]
    
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    atype = random.choice(attack_types)
    ip = random.choice(ips)
    geo = random.choice(geos)
    
    msg = f"Simulated detection of {atype}"
    insert_alert(ts, ip, atype, msg, geo)
    return f"Simulated {atype} from {ip}"

def simulate_advanced_attack():
    """Generates complex scenarios with Active vs Passive distinction"""
    scenarios = [
        # --- ACTIVE ATTACKS (Direct Impact) ---
        {"type": "SQL Injection", "cat": "ACTIVE", "geo": "Russia (Moscow)", "ip": "185.20.50.12"},
        {"type": "Malware Beacon", "cat": "ACTIVE", "geo": "China (Shanghai)", "ip": "14.23.100.99"},
        {"type": "Ransomware Activity", "cat": "ACTIVE", "geo": "North Korea (Pyongyang)", "ip": "175.45.176.8"},
        {"type": "Brute Force (SSH)", "cat": "ACTIVE", "geo": "Brazil (Sao Paulo)", "ip": "191.30.22.45"},
        {"type": "DDoS Flood (UDP)", "cat": "ACTIVE", "geo": "Germany (Berlin)", "ip": "103.10.5.11"},
        
        # --- PASSIVE ATTACKS (Reconnaissance) ---
        {"type": "Port Scan (Stealth)", "cat": "PASSIVE", "geo": "United States (Chicago)", "ip": "45.12.33.1"},
        {"type": "Packet Sniffing", "cat": "PASSIVE", "geo": "Unknown (Tor Node)", "ip": "198.51.100.22"},
        {"type": "OS Fingerprinting", "cat": "PASSIVE", "geo": "France (Paris)", "ip": "51.15.10.55"},
        {"type": "Traffic Analysis", "cat": "PASSIVE", "geo": "Netherlands (Amsterdam)", "ip": "88.198.5.2"}
    ]
    s = random.choice(scenarios)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # We append the category to the message so it appears in the logs
    insert_alert(ts, s['ip'], s['type'], f"[{s['cat']}] Detected signature", s['geo'])
    return f"🔥 {s['cat']}: {s['type']} from {s['geo']}"

# --- AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_role" not in st.session_state:
    st.session_state["user_role"] = None

if not st.session_state["authenticated"]:
    # Login Background & Sound
    st.markdown("""
    <style>
        .stApp {
            background-image: linear-gradient(rgba(0, 0, 0, 0.7), rgba(0, 0, 0, 0.9)), 
            url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }
        .login-container-bg {
            background: rgba(10, 10, 15, 0.85); 
            border: 1px solid #00ff41; 
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0px 0px 50px rgba(0, 255, 65, 0.2);
            text-align: center;
            max-width: 450px;
            margin: 0 auto;
            backdrop-filter: blur(5px);
        }
        .stTextInput input { background-color: #000; color: #00ff41; border: 1px solid #333; }
    </style>
    
    <audio autoplay>
        <source src="https://cdn.pixabay.com/audio/2022/03/24/audio_34b6840331.mp3" type="audio/mpeg">
    </audio>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown('<div class="login-container-bg">', unsafe_allow_html=True)
        st.image("https://cdn-icons-png.flaticon.com/512/2438/2438078.png", width=100)
        st.markdown('<h2 style="color:#00ff41; font-family:Courier New">🔐 ACCESS CONTROL</h2>', unsafe_allow_html=True)
        
        with st.form("login_form"):
            user = st.text_input("Username", placeholder="e.g. admin")
            pwd = st.text_input("Password", type="password", placeholder="••••••")
            c1, c2 = st.columns(2)
            with c1: role = st.selectbox("Role", ["Admin", "Security Analyst"])
            with c2: 
                st.write("") 
                st.write("")
                remember = st.checkbox("Remember Me")
            
            if st.form_submit_button("AUTHENTICATE", use_container_width=True):
                if user in CREDENTIALS and CREDENTIALS[user] == pwd:
                    st.session_state["authenticated"] = True
                    st.session_state["user_role"] = role
                    insert_log(user, f"Logged in as {role}")
                    st.success(f"Welcome back, {user}!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Invalid Credentials")
        st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# --- MAIN DASHBOARD ---

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2438/2438078.png", width=50)
    st.title("🛡️ CyberGuard")
    st.caption(f"Logged in as: {st.session_state.get('user_role', 'Admin')}")
    st.markdown("---")
    
    # VFX CONTROLS
    st.subheader("🖥️ Interface FX")
    enable_vfx = st.toggle("Enable Hacker Mode (VFX)", value=True)
    refresh_rate = st.slider("Refresh Rate (s)", 1, 60, 2)
    
    st.markdown("---")
    
    # Live Operations
    st.subheader("⚡ Live Operations")
    
    auto_sim = st.toggle("🤖 Auto-Simulate", value=False)
    
    if st.button("🔴 Trigger Advanced Attack", use_container_width=True):
        res = simulate_advanced_attack()
        st.toast(res, icon="🔥")

    st.subheader("📡 Active Hostiles")
    df = get_data() 
    if not df.empty:
        active = df['src_ip'].unique()[:5]
        for ip in active:
            st.code(f"🔴 {ip}")
    else:
        st.caption("No active threats.")
    st.markdown("---")

    # Filters
    st.subheader("🔎 Filters")
    ignored_ips = get_ignored_ips()
    filtered_df = df.copy() 
    if not df.empty:
        filtered_df = filtered_df[~filtered_df["src_ip"].isin(ignored_ips)]
        status_filter = st.selectbox("Status", ["All", "new", "reviewed", "false positive"])
        if status_filter != "All":
            filtered_df = filtered_df[filtered_df["status"] == status_filter]
        type_filter = st.multiselect("Attack Type", filtered_df["attack_type"].unique(), default=filtered_df["attack_type"].unique())
        if type_filter:
            filtered_df = filtered_df[filtered_df["attack_type"].isin(type_filter)]
            
    st.markdown("---")
    if st.button("LOGOUT", use_container_width=True):
        st.session_state["authenticated"] = False
        st.rerun()

# --- AUTO-REFRESH & SIMULATION ---
st_autorefresh(interval=refresh_rate * 1000, key="soc_refresh")

if auto_sim:
    simulate_advanced_attack()

# --- CUSTOM CSS & VFX ENGINE ---
base_css = """
<style>
    .stApp {
        background-color: #050505;
        background-image: radial-gradient(circle at 50% 50%, #111111 0%, #050505 100%);
        color: #e0e0e0;
    }
    h1, h2, h3 { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e0e0e0; font-weight: 600; }
    [data-testid="stSidebar"] { background-color: #0a0a0a; border-right: 1px solid #222; }
    
    /* Metric Cards */
    .metric-card {
        background: #121212;
        border-left: 4px solid #00d4ff;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        margin-bottom: 10px;
    }
    .metric-title { color: #888; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
    .metric-value { color: #fff; font-size: 1.8rem; font-weight: bold; }
    
    /* Color Codes */
    .metric-card.danger { border-left-color: #ff4b4b; } /* Red for Active */
    .metric-card.warning { border-left-color: #ffa500; } /* Orange for Passive */
    .metric-card.success { border-left-color: #00cc96; } /* Green for System */
</style>
"""
st.markdown(base_css, unsafe_allow_html=True)

if enable_vfx:
    vfx_css = """
    <style>
        .crt::before {
            content: " "; display: block; position: fixed; top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 2; background-size: 100% 2px, 3px 100%; pointer-events: none;
        }
        @keyframes glitch {
            0% { transform: translate(0) } 20% { transform: translate(-2px, 2px) } 40% { transform: translate(-2px, -2px) }
            60% { transform: translate(2px, 2px) } 80% { transform: translate(2px, -2px) } 100% { transform: translate(0) }
        }
        .glitch-title {
            font-family: 'Courier New', Courier, monospace; font-weight: bold; color: #00ff41;
            text-shadow: 2px 2px #ff0000; animation: glitch 1s infinite;
        }
        @keyframes pulse-red {
            0% { box-shadow: 0 0 0 0 rgba(255, 75, 75, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(255, 75, 75, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 75, 75, 0); }
        }
        .metric-card.danger { animation: pulse-red 2s infinite; }
    </style>
    """
    st.markdown(vfx_css, unsafe_allow_html=True)
    st.markdown('<div class="crt"></div>', unsafe_allow_html=True)


# --- SINGLE PAGE LAYOUT ---

# Header
current_time = datetime.datetime.now().strftime("%H:%M:%S")
if enable_vfx:
    st.markdown(f"""
        <h2 class="glitch-title">📡 SOC COMMAND CENTER_</h2>
        <span style="float:right; font-size: 0.8em; color: #00ff41; border: 1px solid #00ff41; padding: 5px 10px; border-radius: 5px;">
        🟢 LIVE | Updated: {current_time}
        </span><br>""", unsafe_allow_html=True)
else:
    st.markdown(f"""
        ## 📡 SOC Command Center 
        <span style="float:right; font-size: 0.8em; color: #00cc96; border: 1px solid #00cc96; padding: 5px 10px; border-radius: 5px;">
        🟢 LIVE | Updated: {current_time}
        </span>""", unsafe_allow_html=True)


# Global Threat Map
if not filtered_df.empty:
    with st.expander("🌍 Global Threat Map", expanded=True):
        coords = {
            "China": [35.8617, 104.1954], "Russia": [61.5240, 105.3188],
            "United States": [37.0902, -95.7129], "Germany": [51.1657, 10.4515],
            "Brazil": [-14.2350, -51.9253], "North Korea": [40.3399, 127.5101],
            "France": [46.2276, 2.2137], "Netherlands": [52.1326, 5.2913]
        }
        map_data = []
        for index, row in filtered_df.head(50).iterrows():
            country = row['geolocation'].split("(")[0].strip()
            if country in coords:
                map_data.append({"lat": coords[country][0], "lon": coords[country][1]})
            else:
                map_data.append({"lat": random.uniform(-50, 70), "lon": random.uniform(-100, 140)})
        
        map_df = pd.DataFrame(map_data)
        if not map_df.empty:
            st.map(map_df, zoom=1, use_container_width=True)

# 1. KPI Cards (UPDATED FOR ACTIVE / PASSIVE)
if not df.empty:
    total = len(df)
    
    # Define keywords for Active vs Passive
    active_keywords = "Brute|DoS|SQL|Ransomware|Malware|Injection|Active"
    passive_keywords = "Scan|Sniffing|Fingerprinting|Analysis|Passive"
    
    active_count = len(df[df['attack_type'].str.contains(active_keywords, case=False, na=False)])
    passive_count = len(df[df['attack_type'].str.contains(passive_keywords, case=False, na=False)])
    
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.markdown(f'<div class="metric-card"><div class="metric-title">Total Incidents</div><div class="metric-value">{total}</div></div>', unsafe_allow_html=True)
    with c2: st.markdown(f'<div class="metric-card danger"><div class="metric-title">Active Attacks</div><div class="metric-value">{active_count}</div></div>', unsafe_allow_html=True)
    with c3: st.markdown(f'<div class="metric-card warning"><div class="metric-title">Passive Recon</div><div class="metric-value">{passive_count}</div></div>', unsafe_allow_html=True)
    with c4: st.markdown(f'<div class="metric-card success"><div class="metric-title">System Status</div><div class="metric-value" style="color:#00cc96;">ONLINE</div></div>', unsafe_allow_html=True)

# 2. Analytics (Embedded)
if not filtered_df.empty:
    with st.expander("📊 Threat Intelligence Visuals", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            st.caption("Attack Distribution")
            try:
                import plotly.express as px
                fig = px.pie(filtered_df, names='attack_type', hole=0.4, template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
            except:
                st.bar_chart(filtered_df['attack_type'].value_counts())
        with col2:
            st.caption("Traffic Velocity (Last 24h)")
            filtered_df['timestamp'] = pd.to_datetime(filtered_df['timestamp'])
            timeline = filtered_df.set_index('timestamp').resample('h').size()
            st.line_chart(timeline)

# 3. Live Alerts Feed
col_head, col_btn = st.columns([4, 1])
with col_head:
    st.markdown("### 🚨 Live Threat Feed")
with col_btn:
    if not filtered_df.empty:
        csv = convert_df_to_csv(filtered_df)
        st.download_button("💾 Export CSV", csv, 'ids_alert_log.csv', 'text/csv')

if filtered_df.empty:
    st.info("System Secure. No threats detected.")
else:
    for idx, row in filtered_df.head(15).iterrows():
        icon = "⚠️"
        at = row['attack_type']
        
        # Icon Logic
        if "Brute" in at: icon = "🔒"
        elif "DoS" in at: icon = "💥"
        elif "SQL" in at: icon = "💉"
        elif "Malware" in at: icon = "🦠"
        elif "Ransomware" in at: icon = "💀"
        elif "Scan" in at or "Passive" in at: icon = "📡"
        
        with st.expander(f"{icon} {row['timestamp']} | {row['attack_type']} | {row['src_ip']}"):
            col_a, col_b = st.columns([3, 1])
            with col_a:
                st.markdown(f"**Source:** `{row['src_ip']}`")
                st.markdown(f"**Location:** {row['geolocation']}")
                st.markdown(f"**Payload:** {row['message']}")
            with col_b:
                current_status = row['status']
                options = ["new", "reviewed", "false positive"]
                idx = options.index(current_status) if current_status in options else 0
                new_status = st.selectbox("Action", options, key=f"s_{row['id']}", index=idx)
                
                if st.button("Update", key=f"up_{row['id']}"):
                    update_alert_status(row['id'], new_status)
                    st.rerun()
                if st.button("Block IP", key=f"bl_{row['id']}"):
                    ignore_ip(row['src_ip'])
                    st.warning(f"IP {row['src_ip']} ignored.")
                    st.rerun()

# 4. System Management
st.markdown("---")
with st.expander("🛠️ System Management & Simulation (Admin Zone)"):
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.markdown("#### 🧪 Threat Simulator")
        st.caption("Generate fake attacks.")
        if st.button("🚀 Simulate Random Attack", use_container_width=True):
            res = simulate_attack()
            st.success(res)
            time.sleep(1)
            st.rerun()
            
    with m2:
        st.markdown("#### 🧹 Maintenance")
        st.caption("Permanently delete all logs.")
        if st.button("⚠️ Clear All Data", use_container_width=True):
            clear_all_data()
            insert_log("system", "Performed Factory Reset")
            st.warning("System Database Wiped.")
            time.sleep(1)
            st.rerun()
            
    with m3:
        st.markdown("#### 🚫 Firewall Rules")
        st.caption("Manage blocked IPs.")
        ips = get_ignored_ips()
        if ips:
            for ip in ips:
                c1, c2 = st.columns([3, 1])
                c1.code(ip)
                if c2.button("Unblock", key=f"ub_{ip}"):
                    unignore_ip(ip)
                    st.success(f"Removed {ip}")
                    st.rerun()
        else:
            st.info("No active blocks.")

# Logs Section (Bottom)
with st.expander("📜 View Audit Logs"):
    logs = get_logs()
    st.dataframe(logs, use_container_width=True, hide_index=True)
    # Force mobile-friendly scaling
st.markdown('<meta name="viewport" content="width=device-width, initial-scale=1.0">', unsafe_allow_html=True)

# Add this to your existing base_css string
mobile_css = """
<style>
    @media (max-width: 640px) {
        .metric-card {
            padding: 10px;
            margin-bottom: 5px;
        }
        .metric-value {
            font-size: 1.2rem;
        }
        h2 {
            font-size: 1.5rem !important;
        }
    }
</style>
"""
st.markdown(mobile_css, unsafe_allow_html=True)