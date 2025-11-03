import nmap
import json

INTENSITY_MODES = {
    'Stealth': '-sS -T1 --top-ports 50',
    'Balanced': '-sS -sV -T3 --top-ports 100',
    'Aggressive': '-sS -sV -O -T4 -p-',
    'Insane': '-A -T5 --script vuln -p-'
}

INTENSITY_WEIGHTS = {
    'Stealth': 0.2,
    'Balanced': 0.4,
    'Aggressive': 0.6,
    'Insane': 1.0
}

def scan_network(subnet, intensity='Balanced', auth_mode='Safe Scan'):
    nm = nmap.PortScanner()
    
    nmap_args = INTENSITY_MODES.get(intensity, INTENSITY_MODES['Balanced'])
    
    print(f"Starting {intensity} scan on {subnet}...")
    print(f"Nmap arguments: {nmap_args}")
    
    try:
        nm.scan(hosts=subnet, arguments=nmap_args)
    except Exception as e:
        print(f"Error during scan: {e}")
        return []
    
    devices = []
    
    for host in nm.all_hosts():
        device_info = {
            'ip': host,
            'mac': '',
            'hostname': '',
            'os': '',
            'ports': [],
            'intensity': intensity,
            'auth_mode': auth_mode
        }
        
        if 'hostnames' in nm[host] and nm[host]['hostnames']:
            device_info['hostname'] = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'][0]['name'] else ''
        
        if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
            device_info['mac'] = nm[host]['addresses']['mac']
        
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            device_info['os'] = nm[host]['osmatch'][0]['name']
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = nm[host][proto][port]
                service = port_info.get('name', 'unknown')
                version = port_info.get('version', '')
                product = port_info.get('product', '')
                
                device_info['ports'].append({
                    'port': port,
                    'service': service,
                    'version': version,
                    'product': product,
                    'state': port_info.get('state', 'unknown')
                })
        
        devices.append(device_info)
    
    print(f"Scan complete. Found {len(devices)} devices.")
    return devices

def get_intensity_weight(intensity):
    return INTENSITY_WEIGHTS.get(intensity, 0.4)
