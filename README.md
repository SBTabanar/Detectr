# Detectr Pro - Network Intrusion Detection System 📡

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Sniffing-Scapy-red)](https://scapy.net/)
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter-blueviolet)](https://github.com/TomSchimansky/CustomTkinter)

**Detectr Pro** is a lightweight Network Intrusion Detection System (NIDS) designed for real-time traffic analysis and threat detection. Built with security professionals in mind, it provides a clean, modern interface for monitoring network anomalies.

## 🚀 Core Capabilities

- **Real-time Packet Inspection**: Deep packet analysis using Scapy to monitor every bit of traffic on the selected interface.
- **Advanced Threat Detection Rules**:
  - **DoS Attack Monitor**: Tracks packet rates per IP. Triggers alerts when thresholds are exceeded.
  - **Port Scan Detection**: Identifies rapid connection attempts across multiple destination ports from a single source.
  - **ARP Poisoning Protection**: Monitors the ARP table for suspicious MAC address changes associated with static IPs.
- **Interactive Dashboard**: Real-time counters for TCP, UDP, and ARP protocols alongside a cumulative alert system.
- **Dynamic Configuration**: Hot-swap sensitivity thresholds (DoS pps and Port Scan limits) without restarting the capture engine.
- **Automated Logging**: Forensic logging to `detectr.log` for post-incident investigation.

## 🛠️ Technical Stack

- **Engine:** Python 3.11
- **Packet Capture:** Scapy (Network abstraction layer)
- **UI Framework:** CustomTkinter (Modern dark-themed UI)
- **Forensics:** Standard `logging` library

## ⚙️ Installation

### 1. Requirements
- Python 3.8+
- **Windows:** [Npcap](https://npcap.com/) (Must be installed in "WinPcap API-compatible Mode")
- **Linux:** Root privileges and `libpcap-dev`

### 2. Setup
```bash
git clone https://github.com/SBTabanar/detectr.git
cd detectr
pip install -r requirements.txt
```

## 📖 Usage

### Running the System
```bash
# Windows (Must run as Administrator)
python nids.py

# Linux (Must run with sudo)
sudo python3 nids.py
```

1. Select your network interface from the dropdown (if applicable).
2. Adjust **DoS Threshold** and **Scan Limit** based on your network environment.
3. Click **START MONITORING** to begin real-time analysis.

## 🧪 Testing
The project includes a `test_traffic.py` script to simulate various network attacks to verify detection capabilities:
```bash
python test_traffic.py
```

## 🧑‍💻 Author
**Sergei Benjamin Tabanar**
*BS IT Student | Network & Information Security Specialist*
[LinkedIn](https://linkedin.com) • [Portfolio](https://sergeibenjamin.com)