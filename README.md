# Network Discovery MVP

A Flask + Socket.IO dashboard that discovers devices on your local network and visualizes them in real-time with Cytoscape.

## Features
- Real network scan using python-nmap (fallback to ping)
- Device type inference (router, computer, mobile, hotspot, printer, media, IoT, NAS, virtual)
- Real-time updates via WebSockets
- Auto-scan with interval and countdown
- Graceful scan stop support
- JSON API: `GET /api/devices`

## Requirements
- Python 3.13 (use provided `network-discovery-mvp` venv) or Python 3.9+
- Optional: nmap binary installed on your system for advanced scanning

## Setup
```bash
# Option 1: Use provided venv (Windows PowerShell)
# In repo root
./network-discovery-mvp/Scripts/Activate.ps1
pip install -r requirements.txt

# Option 2: Your own venv
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

## Run
```bash
# Start the app (use app_clean.py)
python app_clean.py
# Open http://127.0.0.1:5000
```

If `python-nmap` is installed and the `nmap` binary is available, the scanner will use nmap for discovery; otherwise it falls back to parallel ping.

## Frontend controls
- Start Scan: triggers a one-off scan
- Auto-Scan: toggles recurring scans at the configured interval (30–3600s)
- Clear: resets the visualization and stats

## API
- GET `/api/devices` → `{ devices: { [ip]: {...} }, timestamp }`

## Notes
- On Windows, run terminal as Administrator to improve ARP/MAC detection with nmap.
- Firewalls can block ICMP; results may vary depending on your network.

## License
MIT

