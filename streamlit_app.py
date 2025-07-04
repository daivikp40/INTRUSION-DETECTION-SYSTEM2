# streamlit_app.py
import streamlit as st
import pandas as pd
import sqlite3
import io
from database import update_alert_status, upgrade_db
import datetime

# --- Authentication Section ---
st.title("Simple Intrusion Detection System Dashboard")

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
            st.success("Login successful! Please refresh the page or click Login again to continue.")
            st.stop()
        else:
            st.error("Invalid username or password.")
    st.stop()

# Initialize page state
if "page" not in st.session_state:
    st.session_state["page"] = "alerts"

# --- Dashboard Section (only visible after login) ---
if st.button("Refresh Data"):
    pass  # Streamlit reruns on button click

upgrade_db()

conn = sqlite3.connect("alerts.db")
df = pd.read_sql_query("SELECT id, timestamp, src_ip, attack_type, message, status FROM alerts ORDER BY timestamp DESC", conn)
conn.close()

# Sidebar
st.sidebar.title("IDS Controls")

# (Optional) Multi-page navigation
# page = st.sidebar.radio("Go to", ["Dashboard", "Statistics", "About"])

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

# (Optional) Search box
search_term = st.sidebar.text_input("Search (IP, message, etc.)")

# (Optional) Reset filters button
if st.sidebar.button("Reset Filters"):
    # Reset all filters by clearing session state and showing a message
    st.session_state.clear()
    st.success("Filters reset! Please refresh the page.")
    st.stop()

# Dashboard statistics
if not df.empty:
    total_alerts = len(df)
    reviewed = (df["status"] == "reviewed").sum()
    false_positives = (df["status"] == "false positive").sum()
    important = (df["status"] == "important").sum() if "important" in df["status"].values else 0

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
if st.session_state["page"] == "alerts":
    if not filtered_df.empty:
        col_alerts, col_vis = st.columns([5, 1])
        col_alerts.subheader("All Alerts")
        if col_vis.button("Visualize 📊"):
            st.session_state["page"] = "visualize"
            st.stop()

        # Display alerts partitioned by date, with today expanded by default
        filtered_df = filtered_df.sort_values("timestamp")
        filtered_df['date_only'] = filtered_df['timestamp'].dt.date
        today = datetime.date.today()
        for date, group in sorted(filtered_df.groupby('date_only'), key=lambda x: x[0], reverse=True):
            with st.expander(f"{date}", expanded=(date == today)):
                for idx, row in group.iterrows():
                    cols = st.columns([2, 2, 2, 2, 3, 2, 2])
                    cols[0].write(row['timestamp'])
                    cols[1].write(row['src_ip'])
                    cols[2].write(row['attack_type'])
                    cols[3].write(row['message'])
                    cols[4].write(row['status'])
                    if cols[5].button("Mark Reviewed    ", key=f"reviewed_{row['id']}"):
                        update_alert_status(row['id'], "reviewed")
                        st.success("Status updated! Please refresh the page to see changes.")
                        st.stop()
                    if cols[6].button("Mark False Positive   ", key=f"fp_{row['id']}"):
                        update_alert_status(row['id'], "false positive")
                        st.success("Status updated! Please refresh the page to see changes.")
                        st.stop()
                    st.markdown("---")
    else:
        st.info("No alerts detected yet.")

# Download buttons
import io
if st.session_state["page"] == "alerts":
    if not filtered_df.empty:
        csv = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
           label="Download Filtered as CSV",
           data=csv,
          file_name='alerts_filtered.csv',
          mime='text/csv'
      )

# --- Visualization Section ---
if st.session_state["page"] == "visualize":
    st.title("Alert Visualizations")
    if st.button("Back to Alerts"):
        st.session_state["page"] = "alerts"
        st.stop()

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

