import nmap
import json
from active_scan.deep_scan import perform_deep_scan
import logging

logger = logging.getLogger(__name__)

INTENSITY_MODES = {
    'Stealth': '-sT -T1 --top-ports 50',
    'Balanced': '-sT -sV -T3 --top-ports 100',
    'Aggressive': '-sT -sV -T4 --top-ports 1000',
    'Insane': '-sT -sV -T5 --top-ports 1000'
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
    
    logger.info(f"Starting {intensity} scan on {subnet}...")
    logger.info(f"Nmap arguments: {nmap_args}")
    
    try:
        nm.scan(hosts=subnet, arguments=nmap_args)
    except Exception as e:
        logger.error(f"Error during scan: {e}")
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
        
        if auth_mode == 'Deep Scan':
            logger.info(f"Performing deep scan on {host}...")
            deep_info = perform_deep_scan(device_info)
            device_info['deep_scan_results'] = deep_info
            
            if deep_info.get('ssh_results', {}).get('ssh_accessible'):
                creds = deep_info['ssh_results'].get('credentials_found', {})
                logger.info(f"  [+] SSH access gained with {creds.get('username', 'N/A')}")
                if deep_info['ssh_results'].get('system_info'):
                    logger.info(f"  [+] System info: {deep_info['ssh_results']['system_info'][:80]}...")
        
        devices.append(device_info)
    
    logger.info(f"Scan complete. Found {len(devices)} devices.")
    return devices

def scan_network_with_progress(subnet, intensity='Balanced', auth_mode='Safe Scan', scan_id=None):
    import database
    
    nm = nmap.PortScanner()
    nmap_args = INTENSITY_MODES.get(intensity, INTENSITY_MODES['Balanced'])
    
    logger.info(f"Starting {intensity} scan on {subnet} with progress tracking (scan_id={scan_id})...")
    
    try:
        nm.scan(hosts=subnet, arguments=nmap_args)
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        if scan_id:
            database.update_scan_progress(scan_id, 0, current_host=f"Error: {str(e)}")
        raise
    
    devices = []
    all_hosts = nm.all_hosts()
    total_hosts = len(all_hosts) if all_hosts else 1
    
    for idx, host in enumerate(all_hosts):
        progress = int((idx / total_hosts) * 85)
        
        if scan_id:
            database.update_scan_progress(scan_id, progress, current_host=host, found_devices=len(devices))
        
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
        
        if auth_mode == 'Deep Scan':
            logger.info(f"Performing deep scan on {host}...")
            deep_info = perform_deep_scan(device_info)
            device_info['deep_scan_results'] = deep_info
            
            if deep_info.get('ssh_results', {}).get('ssh_accessible'):
                creds = deep_info['ssh_results'].get('credentials_found', {})
                logger.info(f"  [+] SSH access gained with {creds.get('username', 'N/A')}")
                if deep_info['ssh_results'].get('system_info'):
                    logger.info(f"  [+] System info: {deep_info['ssh_results']['system_info'][:80]}...")
        
        devices.append(device_info)
    
    if scan_id:
        database.update_scan_progress(scan_id, 85, current_host="Scan complete", found_devices=len(devices))
    
    logger.info(f"Scan complete. Found {len(devices)} devices.")
    return devices

def get_intensity_weight(intensity):
    return INTENSITY_WEIGHTS.get(intensity, 0.4)
