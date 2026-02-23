# VulnzxScanX

A multi-interface vulnerability scanner aggregator using Nmap and other tools. Supports CLI, Web, and GUI.

## Features
- **Cross-platform**: Works on Windows and Linux.
- **Three Interfaces**: CLI (`cli.py`), Web (`web_app.py`), and GUI (`vulnzxscanx.py`).
- **IP Rotation**: Optional IP rotation using Tor (experimental).
- **Modern UI**: Web dashboard includes a glassmorphism design.
- **Reliable Engine**: Unified core engine for consistent results across all interfaces.

## Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Ensure `nmap` is installed and in your system PATH.
3. (Optional) For IP rotation, ensure `tor` is installed and running.

## Usage

### 1. Graphical User Interface (Tkinter)
```bash
python vulnzxscanx.py
```

### 2. Web Dashboard (Flask)
```bash
python web_app.py
```
Then open `http://127.0.0.1:5000` in your browser.

### 3. Command Line Interface
```bash
python cli.py --target 127.0.0.1 --type Quick --rotate
```

## Scan Types
- **Quick**: Fast scan of common ports.
- **Full**: Thorough scan of all ports.
- **Intense**: Comprehensive scan with OS detection and scripts.
- **CVE Scan**: Scan for known vulnerabilities using Nmap scripts.

## Troubleshooting
- **Permission Denied**: Some Nmap scans require root/administrator privileges. Run your terminal/command prompt as administrator.
- **IP Rotation Failed**: Ensure the Tor service is running. On Linux, the scanner tries `sudo service tor restart`.
