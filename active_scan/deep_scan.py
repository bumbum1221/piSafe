import paramiko
import socket
import requests
from requests.auth import HTTPBasicAuth

SSH_DEFAULT_USERNAME = 'admin'
SSH_DEFAULT_PASSWORD = 'admin'
SSH_COMMON_CREDENTIALS = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('pi', 'raspberry'),
    ('admin', 'password'),
    ('root', 'password'),
    ('admin', ''),
    ('root', ''),
]

def try_ssh_connection(ip, port=22, timeout=3):
    results = {
        'ssh_accessible': False,
        'firmware_info': None,
        'system_info': None,
        'credentials_found': None,
        'open_files': None,
        'running_processes': None
    }
    
    for username, password in SSH_COMMON_CREDENTIALS:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            results['ssh_accessible'] = True
            results['credentials_found'] = {'username': username, 'password': password}
            
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            system_info = stdout.read().decode('utf-8').strip()
            if system_info:
                results['system_info'] = system_info
            
            stdin, stdout, stderr = ssh.exec_command('cat /proc/version 2>/dev/null || sw_vers 2>/dev/null || ver 2>/dev/null')
            firmware_info = stdout.read().decode('utf-8').strip()
            if firmware_info:
                results['firmware_info'] = firmware_info
            
            stdin, stdout, stderr = ssh.exec_command('ps aux | head -20')
            processes = stdout.read().decode('utf-8').strip()
            if processes:
                results['running_processes'] = processes
            
            stdin, stdout, stderr = ssh.exec_command('lsof 2>/dev/null | head -30 || netstat -an 2>/dev/null | head -30')
            open_files = stdout.read().decode('utf-8').strip()
            if open_files:
                results['open_files'] = open_files
            
            ssh.close()
            break
            
        except paramiko.AuthenticationException:
            continue
        except paramiko.SSHException as e:
            break
        except socket.timeout:
            break
        except Exception as e:
            break
    
    return results

def try_http_info(ip, port=80, timeout=3):
    results = {
        'http_accessible': False,
        'server_header': None,
        'page_title': None,
        'status_code': None
    }
    
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            url = f'{protocol}://{ip}:{port}'
            response = requests.get(url, timeout=timeout, verify=False)
            
            results['http_accessible'] = True
            results['status_code'] = response.status_code
            
            if 'Server' in response.headers:
                results['server_header'] = response.headers['Server']
            
            if '<title>' in response.text:
                start = response.text.find('<title>') + 7
                end = response.text.find('</title>')
                if end > start:
                    results['page_title'] = response.text[start:end].strip()
            
            break
            
        except:
            continue
    
    return results

def perform_deep_scan(device_info):
    ip = device_info.get('ip')
    
    deep_info = {
        'ssh_results': None,
        'http_results': None,
        'additional_info': {}
    }
    
    ssh_results = try_ssh_connection(ip)
    if ssh_results['ssh_accessible']:
        deep_info['ssh_results'] = ssh_results
        
        if ssh_results['system_info']:
            device_info['os'] = ssh_results['system_info'][:100]
        
        if ssh_results['firmware_info']:
            deep_info['additional_info']['firmware'] = ssh_results['firmware_info'][:200]
    
    http_ports = [80, 443, 8080, 8443]
    for port_info in device_info.get('ports', []):
        port_num = port_info.get('port')
        service = port_info.get('service', '')
        
        if service in ['http', 'https'] or port_num in http_ports:
            http_results = try_http_info(ip, port=port_num)
            if http_results['http_accessible']:
                deep_info['http_results'] = http_results
                break
    
    return deep_info
