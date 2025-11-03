# PiSafe - Local Machine Setup Guide

## Important: This is a Python Project (Not Node.js)

**PiSafe is a Python/Flask application**, which means it uses Python and its package managers (pip/uv), **not npm**. npm is for Node.js/JavaScript projects only.

## Quick Start for Local Machine

### Prerequisites

Before you begin, ensure you have:
- **Python 3.11 or higher** installed
- **nmap** installed (required for network scanning)
- **pip** or **uv** (Python package managers)

---

## Method 1: Using UV (Recommended - Fastest)

UV is a modern, fast Python package manager. This is the recommended method.

### Step 1: Install Python 3.11+

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3.11 python3-pip -y
```

**macOS:**
```bash
brew install python@3.11
```

**Windows:**
Download from [python.org](https://www.python.org/downloads/)

### Step 2: Install nmap

**Ubuntu/Debian:**
```bash
sudo apt-get install nmap -y
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from [nmap.org](https://nmap.org/download.html)

### Step 3: Install UV

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# For Windows, use PowerShell:
# irm https://astral.sh/uv/install.ps1 | iex
```

### Step 4: Clone/Download the Project

```bash
# If using git
git clone <your-repository-url>
cd pisafe-security-gateway

# Or download and extract the ZIP file
# Then navigate to the project directory
```

### Step 5: Install Dependencies

```bash
# UV will automatically create a virtual environment and install dependencies
uv sync
```

### Step 6: Set Environment Variables

**Linux/macOS:**
```bash
# Set required environment variables
export SESSION_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NIST_CVE_API_KEY="your-nist-api-key-here"

# Or create a .env file (recommended)
cat > .env << 'EOF'
SESSION_SECRET=your-generated-secret-key-here
NIST_CVE_API_KEY=your-nist-api-key-here
EOF

# Load environment variables
export $(cat .env | xargs)
```

**Windows (PowerShell):**
```powershell
$env:SESSION_SECRET = "your-generated-secret-key"
$env:NIST_CVE_API_KEY = "your-nist-api-key-here"
```

### Step 7: Run the Application

```bash
# Run with UV
uv run python app.py
```

The application will start at: **http://localhost:5000**

---

## Method 2: Using pip and venv (Traditional Method)

If you prefer the traditional Python setup:

### Step 1: Install Python and nmap

Follow the same steps as Method 1 (Steps 1-2)

### Step 2: Clone/Download the Project

Same as Method 1 (Step 4)

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### Step 4: Install Dependencies

```bash
# Install from pyproject.toml
pip install -e .

# Or manually install dependencies:
pip install flask flask-sqlalchemy python-nmap paramiko requests pandas netifaces gunicorn psycopg2-binary email-validator
```

### Step 5: Set Environment Variables

Same as Method 1 (Step 6)

### Step 6: Run the Application

```bash
# Make sure virtual environment is activated
python app.py
```

---

## Running with sudo (For Full Nmap Features)

Some nmap scan modes (SYN scan, OS detection) require root privileges:

**Option 1: Run with sudo**
```bash
sudo -E uv run python app.py
# The -E flag preserves environment variables
```

**Option 2: Set nmap capabilities (Linux only)**
```bash
# Allow nmap to run privileged operations without sudo
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Then run normally
uv run python app.py
```

---

## Configuration

### Generate SESSION_SECRET

```bash
# Generate a secure random key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and use it as your SESSION_SECRET.

### Get NIST CVE API Key (Optional but Recommended)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Register for a free API key
3. Use the key in your environment variables

---

## Accessing the Application

Once running, open your browser and navigate to:

```
http://localhost:5000
```

Or from another device on your network:
```
http://<your-computer-ip>:5000
```

---

## Stopping the Application

Press `Ctrl + C` in the terminal to stop the server.

---

## Production Deployment

For production deployment on a server, use Gunicorn:

```bash
# Install gunicorn (already included in dependencies)
uv run gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 300 app:app
```

For detailed production deployment instructions including systemd service, firewall configuration, and security hardening, see **DEPLOYMENT_GUIDE.md**.

---

## Troubleshooting

### Error: "SESSION_SECRET environment variable must be set"

**Solution:** Set the SESSION_SECRET environment variable:
```bash
export SESSION_SECRET="your-secret-key-here"
```

### Error: "ModuleNotFoundError: No module named 'flask'"

**Solution:** Install dependencies:
```bash
uv sync
# or
pip install -e .
```

### Error: "nmap not found"

**Solution:** Install nmap:
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap
```

### Error: "Permission denied" during scan

**Solution:** Run with sudo or set nmap capabilities:
```bash
sudo -E uv run python app.py
```

### Can't access from other devices

**Solution:** Make sure the app is running on 0.0.0.0 (not 127.0.0.1) and check firewall settings:
```bash
# Allow port 5000 (Ubuntu/Debian)
sudo ufw allow 5000/tcp
```

---

## Why Not npm?

**npm (Node Package Manager)** is specifically designed for Node.js/JavaScript projects. It manages JavaScript packages and runs JavaScript code.

**PiSafe is a Python project** that uses:
- **Flask** (Python web framework)
- **python-nmap** (Python library for nmap)
- **paramiko** (Python SSH library)
- **pandas** (Python data analysis library)

These are all **Python libraries**, not JavaScript packages, so they cannot be installed or run with npm.

### Comparison:

| Feature | npm (Node.js) | pip/uv (Python) |
|---------|---------------|-----------------|
| Language | JavaScript | Python |
| Package file | package.json | pyproject.toml |
| Install command | npm install | pip install / uv sync |
| Run command | npm run | python app.py |

---

## Quick Reference

```bash
# Clone project
cd pisafe-security-gateway

# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Set environment variables
export SESSION_SECRET="your-secret-here"
export NIST_CVE_API_KEY="your-key-here"

# Run
uv run python app.py

# Access at: http://localhost:5000
```

---

## Need Help?

- Check **DEPLOYMENT_GUIDE.md** for detailed deployment instructions
- Review the troubleshooting section above
- Verify all environment variables are set correctly
- Ensure nmap is installed and accessible

Happy scanning! 🛡️
