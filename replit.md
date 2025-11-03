# PiSafe - IoT Security Gateway

## Overview
PiSafe is an IoT Security Gateway that performs active vulnerability scanning with multi-intensity Nmap integration, CVE detection via NVD API, and risk analysis. This is Phase 2 of the project focusing on Active Scanning & Reporting.

## Current State (Phase 2 - Active Scanning & Reporting)
- **Status**: Initial implementation complete
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
│   ├── cve_lookup.py           # NVD API integration with caching
│   └── risk_analyzer.py        # Risk scoring engine
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
**devices table**: Stores scanned device information (IP, MAC, OS, ports, risk level, etc.)
**vulnerabilities table**: Stores CVEs linked to devices

### Key Features Implemented
1. **Multi-Intensity Scanning**: 4 modes (Stealth, Balanced, Aggressive, Insane)
2. **Safe Scan Mode**: Non-intrusive enumeration
3. **CVE Integration**: NVD API lookup with 7-day caching
4. **Risk Scoring**: Formula-based risk calculation (CVSS + open ports + intensity weight)
5. **Flask Dashboard**: Home, Reports, and Device Detail pages
6. **Export Functionality**: CSV and HTML report generation

### Dependencies
- Flask: Web framework
- python-nmap: Nmap integration
- requests: NVD API calls
- pandas: Data processing and CSV export
- SQLite3: Database (built-in)

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
- `/` - Home page with scan configuration form
- `/scan` (POST) - Triggers network scan
- `/reports` - View all scanned devices
- `/device/<id>` - View device details with CVEs
- `/export/csv` - Export scan results as CSV
- `/export/html` - Export scan results as HTML

## Future Enhancements (Next Phases)
- Deep Scan authentication mode with SSH/HTTP credential checks
- Real-time scan progress tracking
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
- 2025-11-03: Initial Phase 2 implementation with all core features
