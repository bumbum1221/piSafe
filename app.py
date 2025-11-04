from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, stream_with_context
import database
from active_scan.scanner import scan_network
from active_scan.cve_lookup import lookup_cves_for_device
from active_scan.risk_analyzer import calculate_risk_score, get_risk_level
from reporting.export_report import export_to_csv, export_to_html
from network_utils import get_local_network, get_all_interfaces
import background_scanner
import json
import os
import re
import logging
import time

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET')
if not app.secret_key:
    logger.critical("SESSION_SECRET environment variable must be set for security!")
    raise RuntimeError("SESSION_SECRET environment variable must be set. Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'")

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
    try:
        device_count = database.get_device_count()
        high_risk_count = database.get_high_risk_count()
        network_info = get_local_network()
        
        if network_info.get('error'):
            flash(f'Network auto-detection issue: {network_info["error"]}. Please verify the subnet manually.', 'warning')
        
        return render_template('home.html', 
                             device_count=device_count,
                             high_risk_count=high_risk_count,
                             network_info=network_info)
    except Exception as e:
        logger.error(f'Error in home route: {e}', exc_info=True)
        flash('An error occurred loading the page. Please try again.', 'danger')
        return render_template('home.html', 
                             device_count=0,
                             high_risk_count=0,
                             network_info={'subnet': 'N/A', 'ip': 'N/A', 'netmask': 'N/A', 'interface': 'N/A', 'error': str(e)})

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
        scan_id = background_scanner.start_scan(subnet, intensity, auth_mode)
        flash(f'Scan started successfully! Tracking ID: {scan_id}', 'info')
        return redirect(url_for('scan_status', scan_id=scan_id))
    except Exception as e:
        logger.error(f'Error starting scan: {e}', exc_info=True)
        flash(f'Error starting scan: {str(e)}', 'danger')
        return redirect(url_for('home'))

@app.route('/scan/status/<int:scan_id>')
def scan_status(scan_id):
    scan = database.get_scan_progress(scan_id)
    if not scan:
        flash('Scan not found', 'danger')
        return redirect(url_for('home'))
    
    return render_template('scan_status.html', scan=scan, scan_id=scan_id)

@app.route('/scan/progress/<int:scan_id>')
def scan_progress(scan_id):
    def generate():
        while True:
            scan = database.get_scan_progress(scan_id)
            if not scan:
                yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                break
            
            data = {
                'progress': scan['progress'],
                'status': scan['status'],
                'current_host': scan['current_host'] or '',
                'found_devices': scan['found_devices'],
                'total_hosts': scan['total_hosts'],
                'error_message': scan['error_message'] or ''
            }
            
            yield f"data: {json.dumps(data)}\n\n"
            
            if scan['status'] in ['completed', 'failed']:
                break
            
            time.sleep(0.5)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

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
    try:
        devices = database.get_all_devices()
        network_info = get_local_network()
        
        nodes = []
        edges = []
        
        gateway_ip = network_info.get('ip', 'Unknown')
        if gateway_ip == 'N/A' or not gateway_ip:
            gateway_ip = 'Gateway'
        
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
    except Exception as e:
        logger.error(f'Error in topology API: {e}', exc_info=True)
        return jsonify({
            'error': 'Failed to generate topology',
            'message': str(e),
            'nodes': [],
            'edges': []
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
