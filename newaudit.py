import socket
import ssl
import json
import logging
import datetime
import struct

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

target = 'github.com'

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    443: 'HTTPS', 3306: 'MySQL',
    5432: 'PostgreSQL', 8080: 'HTTP-Alt',
    3389: 'RDP', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 6379: 'Redis',
    9200: 'Elasticsearch'
}

RISKY_PORTS = [21, 23, 3306, 5432, 3389, 27017, 6379, 9200]
CRITICAL_PORTS = [23, 3389]

WEAK_CIPHERS = ['RC4', 'DES', 'MD5', 'NULL', 
                'EXPORT', 'anon', 'ADH', 'AECDH']

def scan_ports(target):
    logger.info(f"Scanning ports on {target}...")
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                if port in CRITICAL_PORTS:
                    risk = "CRITICAL"
                elif port in RISKY_PORTS:
                    risk = "HIGH"
                else:
                    risk = "LOW"
                
                banner = grab_banner(target, port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "banner": banner
                })
                logger.info(
                    f"Port {port} ({service}) OPEN - Risk: {risk}")
            sock.close()
        except Exception as e:
            logger.error(f"Error on port {port}: {e}")
    return open_ports

def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        for line in banner.split('\n'):
            if 'Server:' in line or 'server:' in line:
                return line.strip()
        return banner[:100].strip() if banner else "No banner"
    except Exception:
        return "Banner grab failed"

def check_anonymous_ftp(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, 21))
        sock.recv(1024)
        sock.send(b'USER anonymous\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        if '331' in response or '230' in response:
            logger.warning("CRITICAL: Anonymous FTP login enabled!")
            return True
        return False
    except Exception:
        return False

def check_ssl(target):
    logger.info(f"Checking SSL/TLS on {target}...")
    result = {
        "ssl_enabled": False,
        "issues": [],
        "cipher": None,
        "protocol": None,
        "cert_info": {}
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=target) as s:
            s.settimeout(3)
            s.connect((target, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            protocol = s.version()

            expire_date = datetime.datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.now()).days

            result["ssl_enabled"] = True
            result["cipher"] = cipher[0]
            result["protocol"] = protocol
            result["cert_info"] = {
                "expires_in_days": days_left,
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "version": cert.get('version', 'Unknown')
            }

            # Check certificate expiry
            if days_left < 0:
                result["issues"].append(
                    "CRITICAL: SSL Certificate has EXPIRED!")
                logger.warning("CRITICAL: Certificate EXPIRED!")
            elif days_left < 30:
                result["issues"].append(
                    f"WARNING: Certificate expires in {days_left} days!")
                logger.warning(f"Certificate expires soon: {days_left} days")
            else:
                logger.info(f"SSL OK - Expires in {days_left} days")

            # Check for weak ciphers
            for weak in WEAK_CIPHERS:
                if weak in str(cipher[0]).upper():
                    result["issues"].append(
                        f"CRITICAL: Weak cipher detected: {cipher[0]}")
                    logger.warning(f"Weak cipher: {cipher[0]}")

            # Check protocol version
            if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                result["issues"].append(
                    f"HIGH: Outdated protocol in use: {protocol}")
                logger.warning(f"Outdated protocol: {protocol}")
            else:
                logger.info(f"Protocol OK: {protocol}")

            # Check key strength
            key_bits = cipher[2]
            if key_bits and key_bits < 128:
                result["issues"].append(
                    f"HIGH: Weak key length: {key_bits} bits")
            else:
                logger.info(f"Key strength OK: {key_bits} bits")

    except ssl.SSLError as e:
        result["issues"].append(f"SSL Error: {str(e)}")
        logger.warning(f"SSL Error: {e}")
    except Exception as e:
        result["issues"].append(f"SSL check failed: {str(e)}")
        logger.warning(f"SSL issue: {e}")
    return result

def check_http_security(target):
    logger.info(f"Checking HTTP security headers on {target}...")
    issues = []
    headers_found = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, 80))
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()

        security_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]

        for header in security_headers:
            if header.lower() in response.lower():
                headers_found[header] = "Present"
                logger.info(f"Security header OK: {header}")
            else:
                headers_found[header] = "MISSING"
                issues.append(f"Missing security header: {header}")
                logger.warning(f"Missing header: {header}")

    except Exception as e:
        logger.error(f"HTTP check failed: {e}")

    return headers_found, issues

def calculate_risk_score(open_ports, ssl_result, 
                         http_issues, anon_ftp):
    score = 0
    
    for port in open_ports:
        if port['risk'] == 'CRITICAL':
            score += 30
        elif port['risk'] == 'HIGH':
            score += 15
        else:
            score += 2

    score += len(ssl_result.get('issues', [])) * 10
    score += len(http_issues) * 5

    if anon_ftp:
        score += 50

    if score == 0:
        return "SECURE", score
    elif score < 20:
        return "LOW", score
    elif score < 50:
        return "MEDIUM", score
    elif score < 80:
        return "HIGH", score
    else:
        return "CRITICAL", score

def generate_report(target, ports, ssl_result,
                   http_headers, http_issues, anon_ftp):
    risk_level, risk_score = calculate_risk_score(
        ports, ssl_result, http_issues, anon_ftp)

    critical = [p for p in ports if p['risk'] == 'CRITICAL']
    high = [p for p in ports if p['risk'] == 'HIGH']

    report = {
        "target": target,
        "scan_time": datetime.datetime.now().isoformat(),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "summary": {
            "total_open_ports": len(ports),
            "critical_ports": len(critical),
            "high_risk_ports": len(high),
            "ssl_issues": len(ssl_result.get('issues', [])),
            "missing_security_headers": len(http_issues),
            "anonymous_ftp": anon_ftp
        },
        "open_ports": ports,
        "ssl_analysis": ssl_result,
        "http_security_headers": http_headers,
        "http_issues": http_issues,
        "all_issues": (
            ssl_result.get('issues', []) + http_issues +
            (["CRITICAL: Anonymous FTP enabled!"] if anon_ftp else [])
        ),
        "recommendations": generate_recommendations(
            ports, ssl_result, http_issues, anon_ftp)
    }

    filename = f"security_report_{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f"Report saved to {filename}")
    return report

def generate_recommendations(ports, ssl_result, 
                             http_issues, anon_ftp):
    recs = []
    risky = [p for p in ports if p['risk'] in ['HIGH', 'CRITICAL']]
    
    if risky:
        recs.append(
            "Close or firewall unnecessary high-risk ports")
    if any('cipher' in i.lower() for i in ssl_result.get('issues', [])):
        recs.append(
            "Upgrade SSL configuration to use strong ciphers only")
    if any('protocol' in i.lower() for i in ssl_result.get('issues', [])):
        recs.append(
            "Disable outdated TLS/SSL protocols, use TLS 1.2 or higher")
    if any('expire' in i.lower() for i in ssl_result.get('issues', [])):
        recs.append("Renew SSL certificate immediately")
    if http_issues:
        recs.append(
            "Implement missing HTTP security headers")
    if anon_ftp:
        recs.append(
            "URGENT: Disable anonymous FTP access immediately")
    if not recs:
        recs.append(
            "System appears well configured — maintain regular scans")
    return recs

# ── RUN SCAN ──
print(f"\n{'='*55}")
print(f"   AUDIT SCANNER - Advanced Security Analyzer v2.0")
print(f"   Target : {target}")
print(f"   Time   : {datetime.datetime.now()}")
print(f"{'='*55}\n")

ports = scan_ports(target)
ssl_result = check_ssl(target)
http_headers, http_issues = check_http_security(target)
anon_ftp = check_anonymous_ftp(target)
report = generate_report(
    target, ports, ssl_result,
    http_headers, http_issues, anon_ftp
)

print(f"\n{'='*55}")
print(f"   SECURITY AUDIT SUMMARY")
print(f"{'='*55}")
print(f"   Target              : {target}")
print(f"   Risk Level          : {report['risk_level']}")
print(f"   Risk Score          : {report['risk_score']}/100")
print(f"   Open Ports          : {report['summary']['total_open_ports']}")
print(f"   Critical Ports      : {report['summary']['critical_ports']}")
print(f"   High Risk Ports     : {report['summary']['high_risk_ports']}")
print(f"   SSL Issues          : {report['summary']['ssl_issues']}")
print(f"   Missing Headers     : {report['summary']['missing_security_headers']}")
print(f"   Anonymous FTP       : {report['summary']['anonymous_ftp']}")
print(f"{'='*55}")

if report['all_issues']:
    print(f"\n   ISSUES FOUND:")
    for issue in report['all_issues']:
        print(f"   ⚠  {issue}")

print(f"\n   RECOMMENDATIONS:")
for rec in report['recommendations']:
    print(f"   → {rec}")
print(f"\n{'='*55}")
print(f"   Full report saved to JSON file")
print(f"{'='*55}\n")