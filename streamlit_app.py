# streamlit_app.py
import streamlit as st
import pandas as pd
import sqlite3
import io
from database import update_alert_status, upgrade_db
import datetime
from database import get_ignored_ips
from streamlit_autorefresh import st_autorefresh
from streamlit_js_eval import streamlit_js_eval

from database import (
    update_alert_status,
    upgrade_db,
    insert_log,
    init_logs_table,
    init_ignore_table,
    ignore_ip,
    unignore_ip,
    get_ignored_ips
)


init_ignore_table()

init_logs_table()
upgrade_db() 

# --- Authentication Section ---
st.title("🛡️ Intrusion Detection System Dashboard")

# Hardcoded credentials (for demo; use env vars or a file for production)
USERNAME = "admin"
PASSWORD = "ids123"

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == USERNAME and password == PASSWORD:
            st.session_state["authenticated"] = True
            st.success("Login successful!")
            insert_log(admin=username, action="Logged in")
            st.rerun()
            
        else:
            st.error("Invalid username or password.")
            st.stop()
    if not st.session_state["authenticated"]:
        st.stop()

if st.sidebar.button("Logout"):
    insert_log(admin=USERNAME, action="Logged out")
    st.session_state.clear()
    st.success("You have been logged out.")
    st.rerun()


# Initialize page state
# if "page" not in st.session_state:
#     st.session_state["page"] = "alerts"

# --- Dashboard Section (only visible after login) ---
if st.button("Refresh Data"):
    pass  # Streamlit reruns on button click

upgrade_db()

# Auto-refresh every 5 seconds
st_autorefresh(interval=5000, key="refresh")

# Load alerts
conn = sqlite3.connect("alerts.db")
df = pd.read_sql_query("SELECT id, timestamp, src_ip, attack_type, message, status, geolocation FROM alerts ORDER BY timestamp DESC", conn)
conn.close()

ignored_ips = get_ignored_ips()
df = df[~df["src_ip"].isin(ignored_ips)]

# --- Notification Section ---
if "last_alert_id" not in st.session_state:
    st.session_state["last_alert_id"] = None

# Define which attack types should trigger notification
NOTIFY_TYPES = {"Brute Force (Live)", "DoS Attempt (Live)", "Unauthorized Access Attempt", "Port Sweep Detected", "Port Scan (Live)"}

if not df.empty:
    latest_id = df.iloc[0]["id"]
    latest_type = df.iloc[0]['attack_type']

    if st.session_state["last_alert_id"] is None:
        st.session_state["last_alert_id"] = latest_id
    elif latest_id != st.session_state["last_alert_id"]:
        if latest_type in NOTIFY_TYPES:
            st.toast(f"🚨 New alert: {latest_type} from {df.iloc[0]['src_ip']}")
            streamlit_js_eval(
                js_expressions=f"""Notification.requestPermission().then(p=>{{if(p==='granted'){{new Notification('🚨 IDS Alert: {latest_type} from {df.iloc[0]['src_ip']}')}}}})""",
                key="notify"
            )
        st.session_state["last_alert_id"] = latest_id


# Sidebar
st.sidebar.title("IDS Controls")

if "go_to_alerts" in st.session_state:
    del st.session_state["go_to_alerts"]
    page = "Alerts"
else:
    pages = ["Alerts", "Visualize", "Logs", "Ignored IPs"]

if "page" not in st.session_state:
    st.session_state.page = "Alerts"

st.session_state.page = st.sidebar.radio("Go to", pages, index=pages.index(st.session_state.page))
page = st.session_state.page




st.sidebar.markdown("### Filters")
status_filter = st.sidebar.selectbox(
    "Status",
    ["All", "new", "reviewed", "false positive", "important", "investigating"]
)
attack_type_filter = st.sidebar.selectbox(
    "Attack Type",
    ["All"] + sorted(df["attack_type"].unique()) if not df.empty else ["All"]
)
group_by_option = st.sidebar.selectbox(
    "Group By",
    ["None", "attack_type", "status", "src_ip"]
)
if not df.empty:
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    date_range = st.sidebar.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
    else:
        start_date = end_date = date_range
else:
    start_date, end_date = None, None


search_term = st.sidebar.text_input("Search (IP, message, etc.)")


if st.sidebar.button("Reset Filters"):
    # Reset all filters by clearing session state and showing a message
    st.session_state.clear()
    st.success("Filters reset! Please refresh the page.")
    st.stop()

# Dashboard statistics
if not df.empty:
    today = datetime.date.today()
    today_alerts = df[df['timestamp'].dt.date == today]

    total_alerts = len(today_alerts)
    reviewed = (today_alerts["status"] == "reviewed").sum()
    false_positives = (today_alerts["status"] == "false positive").sum()
    important = (today_alerts["status"] == "important").sum() if "important" in today_alerts["status"].values else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", total_alerts)
    col2.metric("Reviewed", reviewed)
    col3.metric("False Positives", false_positives)
    col4.metric("Important", important)

# Apply filters
filtered_df = df.copy()
if status_filter != "All":
    filtered_df = filtered_df[filtered_df["status"] == status_filter]
if attack_type_filter != "All":
    filtered_df = filtered_df[filtered_df["attack_type"] == attack_type_filter]
if start_date and end_date:
    filtered_df = filtered_df[
        (filtered_df["timestamp"].dt.date >= start_date) &
        (filtered_df["timestamp"].dt.date <= end_date)
    ]
if search_term:
    filtered_df = filtered_df[
        filtered_df["src_ip"].str.contains(search_term, case=False, na=False) |
        filtered_df["message"].str.contains(search_term, case=False, na=False) |
        filtered_df["attack_type"].str.contains(search_term, case=False, na=False)
    ]

# Display grouped or ungrouped table
if page == "Alerts":
    if not filtered_df.empty:
        st.subheader("All Alerts")

        # Display alerts partitioned by date, with today expanded by default
        filtered_df = filtered_df.sort_values("timestamp")
        filtered_df['date_only'] = filtered_df['timestamp'].dt.date
        today = datetime.date.today()
        for date, group in sorted(filtered_df.groupby('date_only'), key=lambda x: x[0], reverse=True):
            with st.expander(f"{date}", expanded=(date == today)):
                # Sort group by timestamp descending
                group = group.sort_values("timestamp", ascending=False)

                # Calculate metrics for this date
                total_alerts = len(group)
                reviewed = (group["status"] == "reviewed").sum()
                false_positives = (group["status"] == "false positive").sum()
                important = (group["status"] == "important").sum() if "important" in group["status"].values else 0

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Alerts", total_alerts)
                col2.metric("Reviewed", reviewed)
                col3.metric("False Positives", false_positives)
                col4.metric("Important", important)

                for idx, row in group.iterrows():
                    st.markdown("---")
                    cols = st.columns([2, 2, 2, 2.5, 4, 2.5, 2.5, 1])  # Add one more column


                    # 1. Timestamp
                    cols[0].markdown(f"📅 `{row['timestamp']}`")

                    # 2. Source IP
                    cols[1].markdown(f"🌐 `{row['src_ip']}`")

                    # 3. Geolocation
                    geo = row['geolocation']
                    if not geo or geo == "None":
                        geo = "Unknown"
                    cols[2].markdown(f"🗺️ `{geo}`")

                    # 4. Attack Type
                    cols[3].markdown(f"🧠 **{row['attack_type']}**")

                    # 5. Message
                    cols[4].markdown(f"💬 {row['message']}")

                    # 6. Current Status
                    cols[5].markdown(f"🏷️ **{row['status']}**")

                    # 7. New Status Dropdown
                    status_options = ["new", "reviewed", "false positive", "important", "investigating"]
                    current_status = row["status"] if row["status"] in status_options else "new"
                    new_status = cols[6].selectbox(
                        "Change",
                        status_options,
                        index=status_options.index(current_status),
                        key=f"status_{row['id']}"
                    )

                    # 8. Update Button
                    if cols[7].button("✔", key=f"update_{row['id']}"):
                        if new_status != row["status"]:
                            update_alert_status(row["id"], new_status)
                            insert_log(admin=USERNAME, action=f"Updated alert {row['id']} status from {row['status']} to {new_status}")
                            st.success("Status updated!")
                            st.rerun()
                            st.markdown("---")
    else:
        st.info("No alerts detected yet.")

# Download buttons
import io
if page == "Alerts":
    if not filtered_df.empty:
        csv = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
           label="Download Filtered as CSV",
           data=csv,
          file_name='alerts_filtered.csv',
          mime='text/csv'
      )

# --- Visualization Section ---
if page == "Visualize":
    st.title("Alert Visualizations")
    if st.button("Back to Alerts"):
        st.session_state["go_to_alerts"] = True
        st.rerun()

    st.subheader("Attack Type Distribution")
    attack_counts = filtered_df["attack_type"].value_counts()
    st.bar_chart(attack_counts)

    st.subheader("Alerts Over Time")
    alerts_per_day = filtered_df.groupby(filtered_df['timestamp'].dt.date).size()
    st.line_chart(alerts_per_day)

    try:
        import plotly.express as px
        st.subheader("Alert Status Distribution")
        status_counts = filtered_df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        fig = px.pie(status_counts, names="Status", values="Count", title="Alert Status Distribution")
        st.plotly_chart(fig)
    except ImportError:
        st.info("Install plotly for pie chart: pip install plotly")

elif page == "Logs":
    st.title("📝 Admin Activity Logs")

    conn = sqlite3.connect("alerts.db")
    logs_df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
    conn.close()

    if not logs_df.empty:
        st.dataframe(logs_df, use_container_width=True)
    else:
        st.info("No log entries recorded yet.")

elif page == "Ignored IPs":
    st.title("🚫 Ignored IPs Management")

    conn = sqlite3.connect("alerts.db")
    full_df = pd.read_sql_query("SELECT src_ip FROM alerts", conn)
    conn.close()
    all_ips = full_df["src_ip"].value_counts()

    ignored_ips = get_ignored_ips()

    if all_ips.empty:
        st.info("No IPs detected yet.")
    else:
        with st.expander("✅ Currently Ignored IPs", expanded=True):
            any_ignored = False
            for ip in ignored_ips:
                if ip in all_ips:
                    any_ignored = True
                    col1, col2 = st.columns([5, 2])
                    col1.markdown(f"🌐 **{ip}** — {all_ips[ip]} alerts")
                    if col2.button("Unignore", key=f"unignore_{ip}"):
                        unignore_ip(ip)
                        insert_log(admin=USERNAME, action=f"Unignored IP {ip}")
                        st.success(f"{ip} is now being monitored again.")
                        st.rerun()
                        if not any_ignored:
                            st.info("No ignored IPs currently found in alerts.")
        with st.expander("📡 Currently Monitored IPs", expanded=False):
            for ip, count in all_ips.items():
                if ip not in ignored_ips:
                    col1, col2 = st.columns([5, 2])
                    col1.markdown(f"🌐 **{ip}** — {count} alerts")
                    if col2.button("Ignore", key=f"ignore_{ip}"):
                        ignore_ip(ip)
                        insert_log(admin=USERNAME, action=f"Ignored IP {ip}")
                        st.success(f"{ip} is now ignored.")
                        st.rerun()
