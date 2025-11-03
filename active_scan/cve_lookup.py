import requests
import json
import os
import time
from datetime import datetime, timedelta

CACHE_FILE = 'cve_cache.json'
CACHE_DURATION = timedelta(days=7)

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
                return cache
        except:
            return {}
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

def search_cves(keyword):
    cache = load_cache()
    
    cache_key = keyword.lower().strip()
    if cache_key in cache:
        cached_entry = cache[cache_key]
        cache_time = datetime.fromisoformat(cached_entry['timestamp'])
        if datetime.now() - cache_time < CACHE_DURATION:
            print(f"Using cached CVE data for '{keyword}'")
            return cached_entry['cves']
    
    print(f"Fetching CVE data for '{keyword}' from NVD API...")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 10
    }
    
    try:
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            if 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', 'No description available') if descriptions else 'No description available'
                    
                    metrics = cve.get('metrics', {})
                    cvss_score = 0.0
                    severity = 'Unknown'
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'Unknown')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = 'Medium' if cvss_score >= 4.0 else 'Low'
                    
                    cves.append({
                        'cve_id': cve_id,
                        'description': description[:200],
                        'severity': severity,
                        'score': cvss_score
                    })
            
            cache[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'cves': cves
            }
            save_cache(cache)
            
            time.sleep(0.6)
            
            return cves
        else:
            print(f"CVE API returned status code {response.status_code}")
            return []
    
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []

def lookup_cves_for_device(device_info):
    all_cves = []
    
    if device_info.get('os'):
        os_keywords = device_info['os'].split()[:3]
        for keyword in os_keywords:
            if len(keyword) > 3:
                cves = search_cves(keyword)
                all_cves.extend(cves)
    
    for port_info in device_info.get('ports', []):
        product = port_info.get('product', '')
        service = port_info.get('service', '')
        
        if product and len(product) > 3:
            cves = search_cves(product)
            all_cves.extend(cves)
        elif service and len(service) > 3:
            cves = search_cves(service)
            all_cves.extend(cves)
    
    seen_cves = set()
    unique_cves = []
    for cve in all_cves:
        if cve['cve_id'] not in seen_cves:
            seen_cves.add(cve['cve_id'])
            unique_cves.append(cve)
    
    return unique_cves
