from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
import database
from active_scan.scanner import scan_network
from active_scan.cve_lookup import lookup_cves_for_device
from active_scan.risk_analyzer import calculate_risk_score, get_risk_level
from reporting.export_report import export_to_csv, export_to_html
from network_utils import get_local_network, get_all_interfaces
import json
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET')
if not app.secret_key:
    raise RuntimeError("SESSION_SECRET environment variable must be set")

database.init_db()

ALLOWED_INTENSITIES = ['Stealth', 'Balanced', 'Aggressive', 'Insane']
ALLOWED_AUTH_MODES = ['Safe Scan', 'Deep Scan']

def validate_subnet(subnet):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    ip_range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$'
    
    if re.match(ip_pattern, subnet) or re.match(cidr_pattern, subnet) or re.match(ip_range_pattern, subnet):
        parts = subnet.split('/')[0].split('-')[0].split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            if '/' in subnet:
                cidr = int(subnet.split('/')[1])
                if 0 <= cidr <= 32:
                    return True
                return False
            return True
    return False

@app.route('/')
def home():
    device_count = database.get_device_count()
    high_risk_count = database.get_high_risk_count()
    network_info = get_local_network()
    
    return render_template('home.html', 
                         device_count=device_count,
                         high_risk_count=high_risk_count,
                         network_info=network_info)

@app.route('/scan', methods=['POST'])
def scan():
    subnet = request.form.get('subnet', '127.0.0.1').strip()
    intensity = request.form.get('intensity', 'Balanced')
    auth_mode = request.form.get('auth_mode', 'Safe Scan')
    
    if not subnet:
        flash('Please enter a subnet to scan', 'danger')
        return redirect(url_for('home'))
    
    if not validate_subnet(subnet):
        flash('Invalid subnet format. Please use valid IP address (e.g., 192.168.1.1) or CIDR notation (e.g., 192.168.1.0/24)', 'danger')
        return redirect(url_for('home'))
    
    if intensity not in ALLOWED_INTENSITIES:
        flash('Invalid scan intensity selected', 'danger')
        return redirect(url_for('home'))
    
    if auth_mode not in ALLOWED_AUTH_MODES:
        flash('Invalid authentication mode selected', 'danger')
        return redirect(url_for('home'))
    
    try:
        devices = scan_network(subnet, intensity, auth_mode)
        
        for device in devices:
            cves = lookup_cves_for_device(device)
            
            risk_score = calculate_risk_score(device, cves)
            risk_level = get_risk_level(risk_score)
            
            ports_str = ', '.join([f"{p['port']}/{p['service']}" for p in device['ports']])
            
            deep_scan_info = None
            if 'deep_scan_results' in device:
                deep_scan_info = json.dumps(device['deep_scan_results'])
            
            device_id = database.add_device(
                ip=device['ip'],
                mac=device['mac'],
                hostname=device['hostname'],
                os=device['os'],
                open_ports=ports_str,
                intensity=device['intensity'],
                auth_mode=device['auth_mode'],
                risk_level=risk_level,
                risk_score=risk_score,
                deep_scan_info=deep_scan_info
            )
            
            for cve in cves:
                database.add_vulnerability(
                    device_id=device_id,
                    cve_id=cve['cve_id'],
                    description=cve['description'],
                    severity=cve['severity'],
                    score=cve['score']
                )
        
        flash(f'Scan completed! Found {len(devices)} device(s).', 'success')
    except Exception as e:
        flash(f'Error during scan: {str(e)}', 'danger')
    
    return redirect(url_for('reports'))

@app.route('/reports')
def reports():
    devices = database.get_all_devices()
    
    devices_with_cve_count = []
    for device in devices:
        device_dict = dict(device)
        vulnerabilities = database.get_vulnerabilities_for_device(device['id'])
        device_dict['cve_count'] = len(vulnerabilities)
        devices_with_cve_count.append(device_dict)
    
    return render_template('reports.html', devices=devices_with_cve_count)

@app.route('/device/<int:device_id>')
def device_detail(device_id):
    device = database.get_device_by_id(device_id)
    if not device:
        flash('Device not found', 'danger')
        return redirect(url_for('reports'))
    
    vulnerabilities = database.get_vulnerabilities_for_device(device_id)
    
    return render_template('scan_detail.html', device=device, vulnerabilities=vulnerabilities)

@app.route('/export/csv')
def export_csv():
    try:
        filename = export_to_csv()
        return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))
    except Exception as e:
        flash(f'Error exporting CSV: {str(e)}', 'danger')
        return redirect(url_for('reports'))

@app.route('/export/html')
def export_html():
    try:
        filename = export_to_html()
        return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))
    except Exception as e:
        flash(f'Error exporting HTML: {str(e)}', 'danger')
        return redirect(url_for('reports'))

@app.route('/topology')
def topology():
    return render_template('topology.html')

@app.route('/api/topology')
def api_topology():
    devices = database.get_all_devices()
    network_info = get_local_network()
    
    nodes = []
    edges = []
    
    gateway_ip = network_info.get('ip', '192.168.1.1')
    nodes.append({
        'id': 'gateway',
        'label': f'Gateway\n{gateway_ip}',
        'type': 'gateway',
        'ip': gateway_ip,
        'shape': 'diamond',
        'color': '#4CAF50',
        'size': 30
    })
    
    for device in devices:
        device_id = f"device_{device['id']}"
        label = f"{device['ip']}\n{device['hostname'] or 'Unknown'}"
        
        color = '#28a745'
        if device['risk_level'] == 'Critical':
            color = '#dc3545'
        elif device['risk_level'] == 'High':
            color = '#fd7e14'
        elif device['risk_level'] == 'Moderate':
            color = '#ffc107'
        
        nodes.append({
            'id': device_id,
            'label': label,
            'type': 'device',
            'ip': device['ip'],
            'mac': device['mac'],
            'os': device['os'],
            'risk_level': device['risk_level'],
            'shape': 'dot',
            'color': color,
            'size': 20
        })
        
        edges.append({
            'from': 'gateway',
            'to': device_id,
            'color': '#999',
            'width': 2
        })
    
    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'network_info': network_info
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
