# INTRUSION-DETECTION-SYSTEM2


This project is a Real-Time Intrusion Detection System (IDS) designed to monitor live network traffic for threats such as brute force SSH attempts and port scans. It features an interactive Streamlit dashboard for managing alerts, visualizing attack trends, and identifying the geolocation of attackers.

🚀 Key Features
Live Detection: Utilizes Scapy to monitor network traffic for real-time threats.

GeoIP Mapping: Integrates the MaxMind GeoLite2 database to provide the country and city of origin for public attacker IPs.

Data Management: Stores all incident data in a persistent SQLite database and allows for exporting filtered alerts as CSV or Excel files.

Interactive Dashboard: A secure management console (default login: admin / ids123) for searching, filtering, and marking alerts as "Reviewed" or "False Positive".

IP Control: Includes functionality to ignore or unignore specific IPs from future alerting.

🛠️ System Requirements & Setup
Dependencies: Install required Python libraries using pip install -r requirements.txt.

Packet Capture: Windows users must install Npcap for live packet capture.

Geolocation: The file GeoLite2-City.mmdb must be placed in the project directory to enable geolocation features.

Network Interface: You may need to manually set your network interface (e.g., iface="Wi-Fi") within live_detection.py.

📊 Execution
To fully operate the system, two components must be run separately:

The Sniffer: Execute python live_detection.py (with Administrator/Sudo privileges) to start real-time monitoring.

The Dashboard: Execute streamlit run streamlit_app.py to launch the web-based visualization interface.

📁 Project Structure
live_detection.py: The core script for real-time threat detection.

streamlit_app.py: The primary file for the interactive dashboard.

database.py: Contains helper functions for database interactions.

alerts.db: The SQLite database where all alert history is stored.
