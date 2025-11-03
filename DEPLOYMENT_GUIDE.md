# PiSafe Security Gateway - Linux Deployment Guide

## Overview
PiSafe Security Gateway is an automated IoT vulnerability scanning tool with real-time network analysis capabilities. This guide will help you deploy and run PiSafe on your Linux machine.

## Features
- **OS & Service Detection**: Automatic detection of operating systems and running services
- **Port Scanning**: Multi-intensity port scanning (Stealth, Balanced, Aggressive, Insane)
- **CVE Matching**: Integration with NIST NVD API for vulnerability matching
- **Risk Classification**: Automated risk scoring and classification (Low, Moderate, High, Critical)
- **Network Topology Map**: Visual network topology with vis.js
- **Report Generation**: Export reports in CSV and HTML formats
- **Firmware Analysis**: Deep scan capabilities with SSH authentication for firmware analysis

## System Requirements

### Hardware
- Minimum: 1GB RAM, 1 CPU core
- Recommended: 2GB+ RAM, 2+ CPU cores
- Storage: 500MB free space

### Software
- **Operating System**: Ubuntu 20.04+, Debian 10+, or any modern Linux distribution
- **Python**: 3.11 or higher
- **Nmap**: Network scanning tool (required)
- **Network**: Access to the network you want to scan

## Installation Steps

### 1. Install System Dependencies

```bash
# Update package lists
sudo apt-get update

# Install Python 3.11+ (if not already installed)
sudo apt-get install python3 python3-pip python3-venv -y

# Install Nmap (REQUIRED for network scanning)
sudo apt-get install nmap -y

# Verify nmap installation
nmap --version
```

### 2. Install UV Package Manager

UV is a fast Python package manager. Install it:

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add UV to PATH (add this to your ~/.bashrc or ~/.zshrc)
export PATH="$HOME/.cargo/bin:$PATH"

# Reload shell or run:
source ~/.bashrc
```

### 3. Clone or Download the Project

```bash
# If using git
git clone <repository-url>
cd pisafe-security-gateway

# Or download and extract the project files
# Then navigate to the project directory
```

### 4. Install Python Dependencies

```bash
# Install all dependencies using UV
uv sync

# This will install:
# - Flask (web framework)
# - Flask-SQLAlchemy (database ORM)
# - python-nmap (nmap Python wrapper)
# - requests (HTTP library for API calls)
# - paramiko (SSH library for deep scanning)
# - pandas (data processing for reports)
# - psycopg2-binary (PostgreSQL support)
# - gunicorn (production WSGI server)
```

### 5. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Create .env file
cat > .env << 'EOF'
# Session secret for Flask (generate a random string)
SESSION_SECRET=your-super-secret-key-change-this

# NIST CVE API Key (optional but recommended)
NIST_CVE_API_KEY=eb9e9d6e-9c0f-49f0-84d6-0a8c2d068503

# Database URL (uses SQLite by default)
# For PostgreSQL: postgresql://user:password@localhost/pisafe
DATABASE_URL=sqlite:///pisafe.db
EOF

# Load environment variables
export $(cat .env | xargs)
```

**Note**: Replace `your-super-secret-key-change-this` with a strong random string.

### 6. Initialize the Database

```bash
# The database will be automatically initialized on first run
# SQLite database will be created at ./pisafe.db
```

## Running the Application

### Development Mode (for testing)

```bash
# Run with UV
uv run python app.py

# Or activate virtual environment and run
source .venv/bin/activate
python app.py
```

The application will start on `http://0.0.0.0:5000`

### Production Mode (recommended)

```bash
# Using Gunicorn (production-ready WSGI server)
uv run gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 300 app:app

# With auto-reload (useful during development)
uv run gunicorn --bind 0.0.0.0:5000 --workers 4 --reload app:app
```

### Running as a Background Service

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/pisafe.service
```

Add the following content:

```ini
[Unit]
Description=PiSafe Security Gateway
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/pisafe-security-gateway
Environment="PATH=/home/your-username/.cargo/bin:/usr/bin"
Environment="SESSION_SECRET=your-super-secret-key"
Environment="NIST_CVE_API_KEY=eb9e9d6e-9c0f-49f0-84d6-0a8c2d068503"
ExecStart=/home/your-username/.cargo/bin/uv run gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Important**: Replace:
- `your-username` with your actual username
- `/path/to/pisafe-security-gateway` with the actual path to the project
- `your-super-secret-key` with your actual secret key

Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable pisafe

# Start the service
sudo systemctl start pisafe

# Check status
sudo systemctl status pisafe

# View logs
sudo journalctl -u pisafe -f
```

## Network Configuration

### Firewall Configuration

Allow access to port 5000:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 5000/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
```

### Running Nmap with Proper Permissions

Nmap requires root privileges for certain scan types (SYN scan, OS detection). You have two options:

**Option 1: Run with sudo (recommended for security scans)**

```bash
# Run the entire application with sudo
sudo -E uv run python app.py
```

**Option 2: Set capabilities on nmap (advanced)**

```bash
# Allow nmap to run privileged operations without sudo
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## Using the Application

### 1. Access the Web Interface

Open your browser and navigate to:
```
http://localhost:5000
```

Or from another machine on the network:
```
http://<your-machine-ip>:5000
```

### 2. Perform a Network Scan

1. **Select Network Subnet**: The application auto-detects your network (e.g., `192.168.1.0/24`)
2. **Choose Scan Intensity**:
   - **Stealth**: Low noise, minimal detection (slow, top 50 ports)
   - **Balanced**: Recommended for most scans (moderate speed, top 100 ports)
   - **Aggressive**: Fast & detailed scanning (all ports, OS detection)
   - **Insane**: Maximum depth, full coverage (all ports, vulnerability scripts)

3. **Select Authentication Mode**:
   - **Safe Scan**: Non-intrusive enumeration
   - **Deep Scan**: Authenticated SSH/HTTP checks for firmware analysis

4. **Click "Start Scan"**

### 3. View Results

- **Reports**: View all scanned devices with risk classifications
- **Network Topology**: Interactive visualization of your network
- **Device Details**: Click on any device to see detailed information and CVEs
- **Export**: Download reports in CSV or HTML format

## API Usage

The application also provides a REST API:

### Get Network Topology Data
```bash
curl http://localhost:5000/api/topology
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'nmap'"

**Solution**: Install dependencies
```bash
uv sync
```

### Issue: "Nmap not found"

**Solution**: Install nmap
```bash
sudo apt-get install nmap -y
```

### Issue: "Permission denied" during scan

**Solution**: Run with sudo or set nmap capabilities
```bash
sudo -E uv run python app.py
# OR
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

### Issue: "No devices found" after scan

**Possible causes**:
1. Incorrect subnet format
2. Firewall blocking ICMP/scans
3. No devices on the network
4. Insufficient permissions

**Solution**: 
- Verify subnet format (e.g., `192.168.1.0/24`)
- Ensure you're on the correct network
- Run with sudo for better scan results

### Issue: CVE lookup failing

**Solution**: Check NIST API key is set correctly
```bash
echo $NIST_CVE_API_KEY
```

### Issue: Application not accessible from other machines

**Solution**: Check firewall settings
```bash
# Allow port 5000
sudo ufw allow 5000/tcp
sudo ufw status
```

## Security Considerations

1. **Run behind a reverse proxy** (nginx, Apache) for production
2. **Use HTTPS** with SSL/TLS certificates
3. **Restrict access** to authorized users only
4. **Change default credentials** for deep scanning
5. **Keep API keys secure** - never commit to version control
6. **Regular updates** - keep dependencies up to date

## Performance Optimization

### For large networks:
- Use **Stealth** or **Balanced** intensity
- Scan subnets in smaller chunks
- Increase Gunicorn timeout: `--timeout 600`

### Database optimization:
- For production, consider PostgreSQL instead of SQLite
- Regular database cleanup of old scans

## Updating the Application

```bash
# Pull latest changes (if using git)
git pull

# Update dependencies
uv sync

# Restart the service
sudo systemctl restart pisafe
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop pisafe
sudo systemctl disable pisafe
sudo rm /etc/systemd/system/pisafe.service
sudo systemctl daemon-reload

# Remove project directory
rm -rf /path/to/pisafe-security-gateway

# Optional: Remove UV
rm -rf ~/.cargo/bin/uv
```

## Support & Documentation

For issues, feature requests, or questions:
- Check the troubleshooting section above
- Review application logs: `sudo journalctl -u pisafe -f`
- Check nmap documentation: `man nmap`

## License

This project is for educational and security research purposes only. Use responsibly and only on networks you own or have permission to scan.
