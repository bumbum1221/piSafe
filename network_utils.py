import netifaces
import socket
import logging

logger = logging.getLogger(__name__)

def get_local_network():
    default_fallback = {
        'subnet': 'N/A',
        'ip': 'N/A',
        'netmask': 'N/A',
        'interface': 'N/A',
        'error': 'Could not detect network'
    }
    
    try:
        gateways = netifaces.gateways()
        
        if gateways is None:
            logger.warning("netifaces.gateways() returned None")
            raise RuntimeError("No gateways detected")
        
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        
        if default_gateway:
            interface = default_gateway[1]
            addrs = netifaces.ifaddresses(interface)
            
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip_address = ip_info.get('addr')
                netmask = ip_info.get('netmask')
                
                if ip_address and netmask:
                    subnet = calculate_subnet(ip_address, netmask)
                    return {
                        'subnet': subnet,
                        'ip': ip_address,
                        'netmask': netmask,
                        'interface': interface,
                        'error': None
                    }
        
        logger.info("Attempting socket-based network detection")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        if local_ip:
            ip_parts = local_ip.split('.')
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return {
                'subnet': subnet,
                'ip': local_ip,
                'netmask': '255.255.255.0',
                'interface': 'auto-detected',
                'error': None
            }
        
        raise RuntimeError("Socket detection failed")
    
    except Exception as e:
        logger.error(f"Error detecting network: {e}")
        return default_fallback

def calculate_subnet(ip, netmask):
    ip_parts = [int(p) for p in ip.split('.')]
    mask_parts = [int(p) for p in netmask.split('.')]
    
    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
    network_address = '.'.join(map(str, network_parts))
    
    cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    
    return f"{network_address}/{cidr}"

def get_all_interfaces():
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                netmask = addr.get('netmask')
                if ip and netmask:
                    subnet = calculate_subnet(ip, netmask)
                    interfaces.append({
                        'interface': iface,
                        'ip': ip,
                        'netmask': netmask,
                        'subnet': subnet
                    })
    return interfaces
