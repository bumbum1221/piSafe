# PiSafe - IoT Security Gateway

## Overview
PiSafe is an IoT Security Gateway that performs active vulnerability scanning with multi-intensity Nmap integration, CVE detection via NVD API, and risk analysis. This is Phase 2 of the project focusing on Active Scanning & Reporting.

## Current State (Phase 2 - Active Scanning & Reporting)
- **Status**: Feature-complete with Deep Scan and cyberpunk UI
- **Last Updated**: November 3, 2025

## Project Architecture

### Backend Structure
```
PiSafe/
├── app.py                      # Flask application with routes
├── database.py                 # SQLite database operations
├── active_scan/
│   ├── __init__.py
│   ├── scanner.py              # Nmap scanning with 4 intensity modes
│   ├── deep_scan.py            # SSH/HTTP authentication and deep scanning
│   ├── cve_lookup.py           # NVD API integration with caching
│   └── risk_analyzer.py        # Risk scoring engine
├── network_utils.py            # Network detection and subnet validation
├── reporting/
│   ├── __init__.py
│   └── export_report.py        # CSV and HTML export functionality
├── templates/                   # Jinja2 HTML templates
│   ├── base.html
│   ├── home.html
│   ├── reports.html
│   └── scan_detail.html
└── static/
    └── style.css               # Bootstrap + custom CSS
```

### Database Schema
**devices table**: Stores scanned device information (IP, MAC, OS, ports, risk level, deep_scan_info, etc.)
**vulnerabilities table**: Stores CVEs linked to devices

The `deep_scan_info` column stores JSON data with SSH and HTTP authentication results.

### Key Features Implemented
1. **Automatic Network Detection**: Auto-detects WiFi/LAN network using netifaces library
2. **Real-time Network Topology**: Interactive network diagram with vis.js showing device connections
3. **Multi-Intensity Scanning**: 4 modes (Stealth, Balanced, Aggressive, Insane)
4. **Deep Scan Mode**: SSH/HTTP authentication attempts with common credentials
   - SSH credential testing (admin/admin, root/root, pi/raspberry, etc.)
   - System information gathering (uname, firmware, running processes)
   - HTTP server detection and information extraction
5. **Safe Scan Mode**: Non-intrusive enumeration
6. **CVE Integration**: NVD API lookup with 7-day caching
7. **Risk Scoring**: Formula-based risk calculation (CVSS + open ports + intensity weight)
8. **Cyberpunk/Hacking UI Theme**: 
   - Dark background with matrix-style effects
   - Cyber green and cyan color scheme
   - Custom fonts (Orbitron, Share Tech Mono)
   - Glowing effects and neon borders
9. **Conditional UI Elements**: Quick Actions only appear after scan completion
10. **Flask Dashboard**: Home, Network Topology, Reports, and Device Detail pages
11. **Export Functionality**: CSV and HTML report generation
12. **Security**: Input validation to prevent command injection attacks

### Dependencies
- Flask: Web framework
- python-nmap: Nmap integration
- paramiko: SSH connection and authentication
- requests: HTTP probing and NVD API calls
- pandas: Data processing and CSV export
- netifaces: Network interface detection
- SQLite3: Database (built-in)
- vis.js: Network topology visualization (CDN)

### System Requirements
**IMPORTANT**: This application requires `nmap` to be installed on the system:
- On Raspberry Pi/Linux: `sudo apt-get install nmap`
- On macOS: `brew install nmap`

### Risk Scoring Formula
```
Risk Score = (Avg CVSS × 1.0) + (OpenPorts × 0.5) + IntensityWeight

Risk Levels:
- Critical: ≥ 8.0
- High: ≥ 5.0
- Moderate: ≥ 2.0
- Low: < 2.0
```

### Intensity Weights
- Stealth: 0.2
- Balanced: 0.4
- Aggressive: 0.6
- Insane: 1.0

## Routes
- `/` - Home page with scan configuration form and auto-detected network
- `/scan` (POST) - Triggers network scan
- `/topology` - Interactive network topology visualization
- `/api/topology` - JSON API for topology data
- `/reports` - View all scanned devices
- `/device/<id>` - View device details with CVEs
- `/export/csv` - Export scan results as CSV
- `/export/html` - Export scan results as HTML

## Future Enhancements (Next Phases)
- Real-time scan progress tracking with WebSocket
- Automated testing for Deep Scan serialization/deserialization
- Rate-limiting and timeout safeguards for Deep Scan on large networks
- Passive monitoring with ML anomaly detection
- Firewall integration for automated threat response
- Email/Telegram alerting system

## Development Notes
- Application binds to `0.0.0.0:5000` for web access
- CVE cache stored in `cve_cache.json` (7-day expiration)
- Reports saved to `reports/` directory
- SQLite database: `pisafe.db`

## User Preferences
None specified yet.

## Recent Changes
- 2025-11-03 (Update 5): Additional UI refinements and documentation:
  - Removed "System Requirement" section from UI for cleaner interface
  - Created LOCAL_SETUP_GUIDE.md with comprehensive local setup instructions
  - Clarified that this is a Python project (not Node.js/npm compatible)
- 2025-11-03 (Update 4): Enhanced security and UI improvements:
  - Changed "Start Network Scan" to "Explicit Scanning" in UI
  - Converted scan intensity from radio buttons to dropdown menu for better UX
  - Enhanced firmware analysis with NIST CVE API key integration for better rate limits
  - Removed hardcoded Flask secret key fallback - SESSION_SECRET now required for security
  - Created comprehensive Linux deployment guide (DEPLOYMENT_GUIDE.md)
  - All sensitive credentials now properly secured via environment variables
- 2025-11-03 (Update 3): Implemented Deep Scan with SSH/HTTP authentication, redesigned entire UI with cyberpunk/hacking theme (dark mode, cyber green/cyan colors, matrix effects), and made Quick Actions conditional (only shows after scan completion)
- 2025-11-03 (Update 2): Added automatic network detection, real-time network topology visualization, removed intensity table, and completely redesigned UI with modern gradients and improved UX
- 2025-11-03 (Initial): Phase 2 implementation with core scanning features
