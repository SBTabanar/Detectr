# Detectr Pro

**Detectr Pro** is a lightweight Network Intrusion Detection System (NIDS) with a modern GUI built using Python, CustomTkinter, and Scapy. It monitors network traffic in real-time to detect potential threats such as Denial of Service (DoS) attempts and Port Scans.

## Features

- **Real-time Packet Monitoring**: Captures and analyzes network packets on the fly.
- **Intrusion Detection Rules**:
  - **High Volume Traffic**: Flags IPs sending an abnormal number of packets (Potential DoS).
  - **Port Scanning**: Detects rapid SYN requests to multiple ports from a single source.
- **Modern GUI**: A dark-themed, user-friendly interface built with `customtkinter`.
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

### Running form Source

1.  Run the application entry point:
    ```bash
    python nids.py
    ```
2.  Click **START DETECTION** to begin monitoring.
3.  Click **STOP** to end the session.

### Running the Executable (Windows)

1.  Navigate to the `dist` folder.
2.  Run `Detectr.exe` as Administrator (often required for packet sniffing).

## Development

- **Run Tests**:
  ```bash
  python test_traffic.py
  ```
- **Build Executable**:
  ```bash
  pyinstaller --noconfirm --onefile --windowed --name "Detectr" --collect-all customtkinter nids.py
  ```

## Credits

- **Author**: SBTabanar
- **Libraries**:
  - [Scapy](https://scapy.net/) (Packet manipulation)
  - [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) (GUI)