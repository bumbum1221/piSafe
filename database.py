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
            scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
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
    
    conn.commit()
    conn.close()

def add_device(ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO devices (ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, mac, hostname, os, open_ports, intensity, auth_mode, risk_level, risk_score))
    
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
