# NetManager CLI

A professional, cross-platform (Linux & Windows) network management CLI tool.

## Features
- Show IP and MAC addresses of devices in the LAN
- Scan devices for RDP (port 3389) status
- Full network scan: IP, MAC, uptime, open ports, RDP status
- Fast, modular, and professional-grade code

## Usage
```bash
netmanager --ip      # Show IP and MAC addresses
netmanager --rdp     # Scan for RDP (port 3389) status
netmanager --all     # Full network scan
```

## Installation
```bash
pip install .
```

## Requirements
- Python 3.7+
- `python-nmap`, `scapy`, `prettytable`

## Cross-platform Launchers
- Windows: Use `netmanager.bat`
- Linux: Use `netmanager.sh` 