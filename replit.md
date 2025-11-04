# PiSafe - IoT Security Gateway

## Overview
PiSafe is an IoT Security Gateway that performs active vulnerability scanning with multi-intensity Nmap integration, CVE detection via NVD API, and risk analysis. This is Phase 2 of the project focusing on Active Scanning & Reporting.

## Current State (Phase 2 - Active Scanning & Reporting)
- **Status**: Production-ready with real-time progress tracking and background scanning
- **Last Updated**: November 4, 2025

## Project Architecture

### Backend Structure
```
PiSafe/
├── app.py                      # Flask application with routes and SSE endpoints
├── database.py                 # SQLite database operations with progress tracking
├── background_scanner.py       # Background scan service with threading
├── active_scan/
│   ├── __init__.py
│   ├── scanner.py              # Nmap scanning with progress reporting
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
│   ├── scan_status.html        # Real-time scan progress page
│   ├── reports.html
│   ├── scan_detail.html
│   └── topology.html
└── static/
    └── style.css               # Bootstrap + custom CSS
```

### Database Schema
**devices table**: Stores scanned device information (IP, MAC, OS, ports, risk level, deep_scan_info, etc.)
**vulnerabilities table**: Stores CVEs linked to devices
**scan_progress table**: Tracks real-time scan progress with status, percentage, current host, and error messages

The `deep_scan_info` column stores JSON data with SSH and HTTP authentication results.

### Key Features Implemented
1. **Automatic Network Detection**: Auto-detects WiFi/LAN network using netifaces library with graceful fallback
2. **Real-time Scan Progress**: Background scanning with Server-Sent Events (SSE) for live progress updates
3. **Real-time Network Topology**: Interactive network diagram with vis.js showing device connections
4. **Multi-Intensity Scanning**: 4 modes (Stealth, Balanced, Aggressive, Insane) - non-privileged nmap modes
5. **Deep Scan Mode**: SSH/HTTP authentication attempts with common credentials
   - SSH credential testing (admin/admin, root/root, pi/raspberry, etc.)
   - System information gathering (uname, firmware, running processes)
   - HTTP server detection and information extraction
6. **Safe Scan Mode**: Non-intrusive enumeration
7. **CVE Integration**: NVD API lookup with 7-day caching
8. **Risk Scoring**: Formula-based risk calculation (CVSS + open ports + intensity weight)
9. **Cyberpunk/Hacking UI Theme**: 
   - Dark background with matrix-style effects
   - Cyber green and cyan color scheme
   - Custom fonts (Orbitron, Share Tech Mono)
   - Glowing effects and neon borders
10. **Conditional UI Elements**: Quick Actions only appear after scan completion
11. **Flask Dashboard**: Home, Network Topology, Reports, Scan Status, and Device Detail pages
12. **Export Functionality**: CSV and HTML report generation
13. **Production Security**: 
    - Enforced SESSION_SECRET environment variable (no hardcoded defaults)
    - Input validation to prevent command injection attacks
    - Comprehensive error handling with detailed logging

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
- `/scan` (POST) - Triggers background network scan
- `/scan/status/<id>` - Real-time scan progress page
- `/scan/progress/<id>` - SSE endpoint for live progress updates
- `/topology` - Interactive network topology visualization
- `/api/topology` - JSON API for topology data
- `/reports` - View all scanned devices
- `/device/<id>` - View device details with CVEs
- `/export/csv` - Export scan results as CSV
- `/export/html` - Export scan results as HTML

## Future Enhancements (Next Phases)
- Automated testing for Deep Scan serialization/deserialization
- Rate-limiting and timeout safeguards for Deep Scan on large networks
- Passive monitoring with ML anomaly detection
- Firewall integration for automated threat response
- Email/Telegram alerting system
- Historical scan comparison and trend analysis

## Development Notes
- Application binds to `0.0.0.0:5000` for web access
- CVE cache stored in `cve_cache.json` (7-day expiration)
- Reports saved to `reports/` directory
- SQLite database: `pisafe.db`

## User Preferences
None specified yet.

## Recent Changes
- 2025-11-04 (Update 6): Production-ready enhancements with real-time progress tracking:
  - **Background Scanning**: Implemented threaded background scan service to prevent UI blocking
  - **Real-time Progress**: Added SSE (Server-Sent Events) endpoint for live scan progress updates
  - **Progress Tracking**: New scan_progress database table tracks status, percentage, current host, and errors
  - **Enhanced Network Detection**: Fixed NoneType errors - network detection now always returns valid data with error field
  - **Non-privileged Scanning**: Changed nmap modes from -sS (requires root) to -sT (TCP connect) for Replit compatibility
  - **Security Hardening**: Removed hardcoded Flask secret key - now enforces SESSION_SECRET environment variable
  - **UI Improvements**: 
    - Changed button text from "Start Scan" to "Scan"
    - Added scan_status.html page with real-time progress bar
    - Network info cards show error indicators when auto-detection fails
    - Error messages displayed with detailed failure reasons
  - **Comprehensive Error Handling**: Added try-catch blocks throughout app.py with proper logging
  - **Production Ready**: All features tested and architect-approved for deployment
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
