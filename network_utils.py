import netifaces
import socket

def get_local_network():
    try:
        gateways = netifaces.gateways()
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
                        'interface': interface
                    }
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        ip_parts = local_ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        return {
            'subnet': subnet,
            'ip': local_ip,
            'netmask': '255.255.255.0',
            'interface': 'unknown'
        }
    
    except Exception as e:
        print(f"Error detecting network: {e}")
        return {
            'subnet': '192.168.1.0/24',
            'ip': '192.168.1.1',
            'netmask': '255.255.255.0',
            'interface': 'unknown'
        }

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
