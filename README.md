# Detectr Pro

**Detectr Pro** is a lightweight Network Intrusion Detection System (NIDS) with a modern GUI built using Python, CustomTkinter, and Scapy. It monitors network traffic in real-time to detect potential threats such as Denial of Service (DoS) attempts and Port Scans.

## Features

- **Real-time Packet Monitoring**: Captures and analyzes network packets on the fly.
- **Intrusion Detection Rules**:
  - **High Volume Traffic**: Flags IPs exceeding user-defined packet rates (Potential DoS).
  - **Port Scanning**: Detects rapid SYN requests to multiple ports from a single source.
  - **ARP Spoofing**: Alerts when a known IP address changes its MAC address.
- **Traffic Dashboard**: Real-time statistics for Total, TCP, UDP, ARP, and Alert counts.
- **Configurable Thresholds**: Adjust DoS limits (pps) and Port Scan sensitivity directly from the GUI.
- **Modern GUI**: A high-contrast, dark-themed interface built with `customtkinter`.
- **Logging**:
  - **Live Console**: displays alerts and status updates in the application window.
  - **File Logging**: Saves all events to `detectr.log` for post-analysis.
- **Cross-Platform**: Compatible with Windows (requires Npcap) and Linux (requires Root).

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/detectr.git
    cd detectr
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Packet Capture Driver (Windows Only)**:
    - Download and install **Npcap** from [https://npcap.com/](https://npcap.com/).
    - **Important**: During installation, ensure you check "Install Npcap in WinPcap API-compatible Mode".

## Usage

### Configuration & Dashboard
- **Detection Thresholds**: Before starting, you can adjust the sensitivity of the intrusion detection rules in the sidebar:
  - **DoS Limit (pps)**: The maximum number of packets per second allowed from a single IP before alerting.
  - **Scan Limit (ports)**: The number of unique destination ports a single IP can target before being flagged as a port scan.
- **Traffic Statistics**: The main dashboard displays real-time counters for:
  - **Total**: Total packets captured.
  - **TCP/UDP/ARP**: Breakdown by protocol.
  - **Alerts**: Cumulative count of security alerts triggered.

### Running from Source

1.  Run the application entry point:
    ```bash
    python nids.py
    ```
2.  Adjust thresholds if necessary (default: 100 pps, 15 ports).
3.  Click **START MONITORING** to begin monitoring.
4.  Click **STOP SESSION** to end the session.

### Running the Executable (Windows)

1.  Navigate to the `dist` folder.
2.  Right-click `Detectr.exe` and select **Run as Administrator** (required for raw packet capture).

## Troubleshooting

- **No Packets Detected**: Ensure you are running as Administrator (Windows) or Root (Linux). Check that Npcap is installed with "WinPcap API-compatible Mode" enabled.
- **Visual Glitches**: If the GUI looks incorrect, ensure you have the `customtkinter` assets collected properly during the build process (already handled by the build script).
- **False Positives**: If you see too many alerts, try increasing the "DoS Limit" or "Scan Limit" in the sidebar.

## Development

- **Run Tests**:
  ```bash
  python test_traffic.py
  ```
- **Build Executable**:
  ```bash
  # Using the included batch file (Windows)
  build.bat
  
  # Manual Build command
  python -m PyInstaller --noconfirm --onefile --windowed --name "Detectr" --collect-all customtkinter nids.py
  ```

## Credits

- **Author**: SBTabanar
- **Libraries**:
  - [Scapy](https://scapy.net/) (Packet manipulation)
  - [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) (GUI)