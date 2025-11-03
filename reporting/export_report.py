import pandas as pd
import database
from datetime import datetime
import os

def export_to_csv(filename=None):
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'reports/scan_{timestamp}.csv'
    
    devices = database.get_all_devices()
    
    data = []
    for device in devices:
        device_id = device['id']
        vulnerabilities = database.get_vulnerabilities_for_device(device_id)
        cve_count = len(vulnerabilities)
        
        data.append({
            'Device IP': device['ip'],
            'MAC Address': device['mac'],
            'Hostname': device['hostname'],
            'OS': device['os'],
            'Open Ports': device['open_ports'],
            'Risk Level': device['risk_level'],
            'Risk Score': device['risk_score'],
            'Intensity': device['intensity'],
            'Auth Mode': device['auth_mode'],
            'CVE Count': cve_count,
            'Scan Time': device['scan_time']
        })
    
    df = pd.DataFrame(data)
    
    os.makedirs('reports', exist_ok=True)
    df.to_csv(filename, index=False)
    
    return filename

def export_to_html(filename=None):
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'reports/scan_{timestamp}.html'
    
    devices = database.get_all_devices()
    
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PiSafe Scan Report</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { padding: 20px; }
            .risk-critical { background-color: #dc3545; color: white; }
            .risk-high { background-color: #fd7e14; color: white; }
            .risk-moderate { background-color: #ffc107; color: black; }
            .risk-low { background-color: #28a745; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mb-4">PiSafe Network Scan Report</h1>
            <p class="text-muted">Generated: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <table class="table table-striped table-bordered">
                <thead class="table-dark">
                    <tr>
                        <th>Device IP</th>
                        <th>MAC Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>CVE Count</th>
                        <th>Intensity</th>
                        <th>Scan Time</th>
                    </tr>
                </thead>
                <tbody>
    '''
    
    for device in devices:
        device_id = device['id']
        vulnerabilities = database.get_vulnerabilities_for_device(device_id)
        cve_count = len(vulnerabilities)
        
        risk_class = f"risk-{device['risk_level'].lower()}"
        
        html += f'''
                    <tr>
                        <td>{device['ip']}</td>
                        <td>{device['mac'] or 'N/A'}</td>
                        <td>{device['hostname'] or 'N/A'}</td>
                        <td>{device['os'] or 'Unknown'}</td>
                        <td>{device['open_ports']}</td>
                        <td class="{risk_class}">{device['risk_level']}</td>
                        <td>{device['risk_score']:.2f}</td>
                        <td>{cve_count}</td>
                        <td>{device['intensity']}</td>
                        <td>{device['scan_time']}</td>
                    </tr>
        '''
    
    html += '''
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''
    
    os.makedirs('reports', exist_ok=True)
    with open(filename, 'w') as f:
        f.write(html)
    
    return filename
