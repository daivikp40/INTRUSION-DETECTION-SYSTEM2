# Real-Time Intrusion Detection System (IDS)

A real-time IDS that detects brute force SSH attempts and port scans from live network traffic, stores alerts in SQLite, and provides a modern Streamlit dashboard for visualization, management, and geolocation of attackers.

---

## 🚀 Features

- **Live Detection:** Detects brute force SSH login attempts and port scanning using Scapy.
- **GeoIP Mapping:** Shows country/city for public attacker IPs using MaxMind GeoLite2 database.
- **Alert Storage:** Stores all alerts in a persistent SQLite database.
- **Interactive Dashboard:** Streamlit dashboard for filtering, grouping, searching, and managing alerts.
- **Visualizations:** Built-in charts for attack types, alert status, and trends over time.
- **Export:** Download filtered alerts as CSV or Excel.
- **Ignored IP Management:** Easily ignore or unignore IPs from alerting.
- **Customizable:** Adjust detection thresholds, filters, and network interface.

---

## 🛠️ Setup

### 1. Install Dependencies

```sh
pip install -r requirements.txt
```

### 2. Install System Requirements

- **Npcap** (Windows only): Required for packet capture. [Download here](https://nmap.org/npcap/)
- **nmap** (optional): For generating test traffic. [Download here](https://nmap.org/download.html)
- **GeoLite2-City.mmdb**: Download the MaxMind GeoLite2 City database for geolocation. [Download here](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
  - Place `GeoLite2-City.mmdb` in your project directory.

### 3. Run the Live Detection Script

> **On Windows:** Run your terminal as Administrator  
> **On Linux:** Use `sudo`

```sh
python live_detection.py
```
- **Tip:** Edit `live_detection.py` to set your correct network interface (e.g., `iface="Wi-Fi"`).

### 4. Start the Streamlit Dashboard

```sh
streamlit run streamlit_app.py
```

---

## 📊 Usage

- **Login** with the default credentials (`admin` / `ids123`).
- **Filter, search, and group** alerts using the sidebar.
- **View attacker geolocation** (country/city) for public IPs in the alert list.
- **Mark alerts** as reviewed, false positive, or important.
- **Visualize** trends and distributions with the "Visualize" button.
- **Download** filtered alerts as CSV or Excel.
- **Ignore/Unignore IPs** from alerting in the "Ignored IPs" section.

---

## ⚡ Testing

- Use `nmap` from another machine, VPN, or cloud server to generate port scans:
  ```sh
  nmap -sT -p 22,80,443 <IDS_IP>
  ```
- For brute force SSH detection, simulate repeated SSH connection attempts to port 22.
- To test geolocation, scan your IDS from a public IP (not a private/local IP).

---

## 📁 Project Structure

```
.
├── live_detection.py      # Real-time detection script
├── streamlit_app.py       # Streamlit dashboard
├── database.py            # Database helper functions
├── alerts.db              # SQLite database (auto-created)
├── requirements.txt       # Python dependencies
├── GeoLite2-City.mmdb     # GeoIP database (download separately)
├── README.md              # This file
└── pages/                 # (Optional) Extra Streamlit pages
```

---

## 📝 Notes

- The dashboard only displays results; detection must be run separately.
- You may need to adjust the network interface or filter in `live_detection.py` for your environment.
- For SSH brute force detection, actual SSH traffic must be present on your network.
- **Npcap** must be installed on Windows for packet capture.
- **GeoLite2-City.mmdb** is required for geolocation features.
- **nmap** is not required for the IDS, but useful for testing.

---

## 🙋 FAQ

**Q: Why don't I see any alerts?**  
A: Make sure `live_detection.py` is running and your network has relevant traffic.

**Q: Why is geolocation "Unknown" for some IPs?**  
A: Private/local IPs and some public IPs may not be present in the GeoLite2 database.

**Q: Why can't I select a date range?**  
A: Only dates with alerts are selectable. Generate alerts on different days for a wider range.

**Q: How do I reset filters?**  
A: Use the "Reset Filters" button in the sidebar.

**Q: Why do I see alerts from many countries?**  
A: Any public-facing device will be scanned by bots and attackers from around the world.

---

## 📧 Contact

For questions or suggestions, open an issue or contact the project maintainer.

---