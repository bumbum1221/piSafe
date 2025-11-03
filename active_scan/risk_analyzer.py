from active_scan.scanner import get_intensity_weight

def calculate_risk_score(device_info, cves):
    if not cves:
        avg_cvss = 0.0
    else:
        total_cvss = sum([cve.get('score', 0.0) for cve in cves])
        avg_cvss = total_cvss / len(cves)
    
    open_ports = len(device_info.get('ports', []))
    
    intensity = device_info.get('intensity', 'Balanced')
    intensity_weight = get_intensity_weight(intensity)
    
    risk_score = (avg_cvss * 1.0) + (open_ports * 0.5) + intensity_weight
    
    return risk_score

def get_risk_level(risk_score):
    if risk_score >= 8.0:
        return 'Critical'
    elif risk_score >= 5.0:
        return 'High'
    elif risk_score >= 2.0:
        return 'Moderate'
    else:
        return 'Low'
