import sqlite3
from datetime import datetime
import os

DB_PATH = 'pisafe.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            os TEXT,
            open_ports TEXT,
            intensity TEXT,
            auth_mode TEXT,
            risk_level TEXT,
            risk_score REAL,
            deep_scan_info TEXT,
            scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE devices ADD COLUMN deep_scan_info TEXT')
    except sqlite3.OperationalError:
        pass
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            cve_id TEXT,
            description TEXT,
            severity TEXT,
            score REAL,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet TEXT NOT NULL,
            intensity TEXT,
            auth_mode TEXT,
            status TEXT DEFAULT 'running',
            progress INTEGER DEFAULT 0,
            current_host TEXT,
            total_hosts INTEGER DEFAULT 0,
            found_devices INTEGER DEFAULT 0,
            error_message TEXT,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME
        )
    ''')
    
    conn.commit()
    conn.close()

def add_device(ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score, deep_scan_info=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO devices (ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score, deep_scan_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score, deep_scan_info))
    
    device_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return device_id

def add_vulnerability(device_id, cve_id, description, severity, score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO vulnerabilities (device_id, cve_id, description, severity, score)
        VALUES (?, ?, ?, ?, ?)
    ''', (device_id, cve_id, description, severity, score))
    
    conn.commit()
    conn.close()

def get_all_devices():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM devices ORDER BY scan_time DESC')
    devices = cursor.fetchall()
    
    conn.close()
    return devices

def get_device_by_id(device_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
    device = cursor.fetchone()
    
    conn.close()
    return device

def get_vulnerabilities_for_device(device_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM vulnerabilities WHERE device_id = ?', (device_id,))
    vulnerabilities = cursor.fetchall()
    
    conn.close()
    return vulnerabilities

def get_device_count():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM devices')
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def get_high_risk_count():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM devices WHERE risk_level IN ('High', 'Critical')")
    count = cursor.fetchone()[0]
    
    conn.close()
    return count

def create_scan_progress(subnet, intensity, auth_mode, total_hosts):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scan_progress (subnet, intensity, auth_mode, total_hosts, status, progress)
        VALUES (?, ?, ?, ?, 'running', 0)
    ''', (subnet, intensity, auth_mode, total_hosts))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return scan_id

def update_scan_progress(scan_id, progress, current_host=None, found_devices=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    updates = ['progress = ?']
    params = [progress]
    
    if current_host is not None:
        updates.append('current_host = ?')
        params.append(current_host)
    
    if found_devices is not None:
        updates.append('found_devices = ?')
        params.append(found_devices)
    
    params.append(scan_id)
    
    cursor.execute(f'''
        UPDATE scan_progress 
        SET {', '.join(updates)}
        WHERE id = ?
    ''', params)
    
    conn.commit()
    conn.close()

def complete_scan_progress(scan_id, status='completed', error_message=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE scan_progress 
        SET status = ?, end_time = CURRENT_TIMESTAMP, error_message = ?, progress = 100
        WHERE id = ?
    ''', (status, error_message, scan_id))
    
    conn.commit()
    conn.close()

def get_scan_progress(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scan_progress WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    
    conn.close()
    return scan

def get_latest_scan_progress():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scan_progress ORDER BY start_time DESC LIMIT 1')
    scan = cursor.fetchone()
    
    conn.close()
    return scan
