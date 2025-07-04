# Real-Time Intrusion Detection System (IDS)

A simple, real-time IDS that detects brute force SSH attempts and port scans from live network traffic, stores alerts in SQLite, and provides a modern Streamlit dashboard for visualization and management.

---

## 🚀 Features

- **Live Detection:** Detects brute force SSH login attempts and port scanning using Scapy.
- **Alert Storage:** Stores all alerts in a persistent SQLite database.
- **Interactive Dashboard:** Streamlit dashboard for filtering, grouping, searching, and managing alerts.
- **Visualizations:** Built-in charts for attack types, alert status, and trends over time.
- **Export:** Download filtered alerts as CSV or Excel.
- **Customizable:** Easily adjust detection thresholds and filters.

---

## 🛠️ Setup

### 1. Install Dependencies

```sh
pip install -r requirements.txt
```

### 2. Install System Requirements

- **Npcap** (Windows only): Required for packet capture. [Download here](https://nmap.org/npcap/)
- **nmap** (optional): For generating test traffic. [Download here](https://nmap.org/download.html)

### 3. Run the Live Detection Script

> **On Windows:** Run your terminal as Administrator  
> **On Linux:** Use `sudo`

```sh
python live_detection.py
```

### 4. Start the Streamlit Dashboard

```sh
streamlit run streamlit_app.py
```

---

## 📊 Usage

- **Login** with the default credentials (`admin` / `ids123`).
- **Filter, search, and group** alerts using the sidebar.
- **Mark alerts** as reviewed or false positive.
- **Visualize** trends and distributions with the "Visualize" button.
- **Download** filtered alerts as CSV or Excel.

---

## ⚡ Testing

- Use `nmap` from another machine or the same machine to generate port scans:
  ```sh
  nmap -T4 -A -p 1-1000 <IDS_IP>
  ```
- For brute force SSH detection, simulate repeated SSH connection attempts to port 22.

---

## 📁 Project Structure

```
.
├── live_detection.py      # Real-time detection script
├── streamlit_app.py       # Streamlit dashboard
├── database.py            # Database helper functions
├── alerts.db              # SQLite database (auto-created)
├── requirements.txt       # Python dependencies
├── readme.md              # This file
└── pages/                 # (Optional) Extra Streamlit pages
```

---

## 📝 Notes

- The dashboard only displays results; detection must be run separately.
- You may need to adjust the network interface or filter in `live_detection.py` for your environment.
- For SSH brute force detection, actual SSH traffic must be present on your network.
- **Npcap** must be installed on Windows for packet capture.
- **nmap** is not required for the IDS, but useful for testing.

---

## 🙋 FAQ

**Q: Why don't I see any alerts?**  
A: Make sure `live_detection.py` is running and your network has relevant traffic.

**Q: Why can't I select a date range?**  
A: Only dates with alerts are selectable. Generate alerts on different days for a wider range.

**Q: How do I reset filters?**  
A: Use the "Reset Filters" button in the sidebar.

---

## 📧 Contact

For questions or suggestions, open an issue or contact the project maintainer.

---