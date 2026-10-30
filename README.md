# PyShield SOC

PyShield is a Python-based Security Operations Center (SOC)
monitoring project designed to scan networks, capture packets,
classify security events, and generate reports.

## Features

1. Network scanning using Nmap
2. Network packet capture using Wireshark TShark
3. Rule-based threat classification
4. SQLite security event storage
5. Streamlit monitoring dashboard
6. CSV security report generation

## Technologies Used

- Python
- Nmap
- Wireshark TShark
- SQLite
- Streamlit
- Pandas
- Plotly

## Project Structure

- src/ - Main application and threat engine
- network_scanner/ - Nmap scanner
- packet_analyzer/ - Packet capture and analysis
- logs/ - SQLite database
- dashboard/ - Streamlit dashboard
- reports/ - CSV report generator

## Installation

Install dependencies:

pip install streamlit pandas plotly streamlit-autorefresh

Install Nmap and Wireshark separately.

## Run PyShield

Activate the virtual environment:

venv\Scripts\activate

Run the main application:

python -m src.main

Run the dashboard in another terminal:

streamlit run dashboard/app.py

## Limitations

- Threat classification uses predefined rules.
- Packet capture processes a limited number of packets.
- Suricata integration is not enabled.
- This is an educational SOC prototype, not an enterprise SIEM.

## Author
Cybersecurity Project