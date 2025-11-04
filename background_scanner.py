import threading
import database
from active_scan.scanner import scan_network_with_progress
from active_scan.cve_lookup import lookup_cves_for_device
from active_scan.risk_analyzer import calculate_risk_score, get_risk_level
import json
import ipaddress
import logging

logger = logging.getLogger(__name__)

active_scans = {}

def calculate_total_hosts(subnet):
    try:
        if '/' in subnet:
            network = ipaddress.ip_network(subnet, strict=False)
            return network.num_addresses
        elif '-' in subnet:
            ip_range = subnet.split('-')
            start = int(ip_range[0].split('.')[-1])
            end = int(ip_range[1])
            return end - start + 1
        else:
            return 1
    except:
        return 256

def run_background_scan(scan_id, subnet, intensity, auth_mode):
    try:
        logger.info(f"Starting background scan {scan_id} for {subnet}")
        
        total_hosts = calculate_total_hosts(subnet)
        database.update_scan_progress(scan_id, 0, current_host=f"Scanning {subnet}", found_devices=0)
        
        devices = scan_network_with_progress(subnet, intensity, auth_mode, scan_id)
        
        logger.info(f"Scan {scan_id} found {len(devices)} devices, processing CVEs...")
        database.update_scan_progress(scan_id, 90, current_host="Processing vulnerabilities", found_devices=len(devices))
        
        for device in devices:
            try:
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
            except Exception as e:
                logger.error(f"Error processing device {device.get('ip', 'unknown')}: {e}")
        
        database.complete_scan_progress(scan_id, 'completed')
        logger.info(f"Scan {scan_id} completed successfully with {len(devices)} devices")
        
    except Exception as e:
        logger.error(f"Error in background scan {scan_id}: {e}")
        database.complete_scan_progress(scan_id, 'failed', str(e))
    finally:
        if scan_id in active_scans:
            del active_scans[scan_id]

def start_scan(subnet, intensity, auth_mode):
    total_hosts = calculate_total_hosts(subnet)
    scan_id = database.create_scan_progress(subnet, intensity, auth_mode, total_hosts)
    
    thread = threading.Thread(
        target=run_background_scan,
        args=(scan_id, subnet, intensity, auth_mode),
        daemon=True
    )
    
    active_scans[scan_id] = thread
    thread.start()
    
    return scan_id
