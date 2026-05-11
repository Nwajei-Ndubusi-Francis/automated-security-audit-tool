import socket
import ssl
import json
import logging
import datetime

logging.basicConfig(level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

target = 'github.com'

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    443: 'HTTPS', 3306: 'MySQL', 
    5432: 'PostgreSQL', 8080: 'HTTP-Alt'
}

RISKY_PORTS = [21, 23, 3306, 5432]

def scan_ports(target):
    logger.info(f"Scanning ports on {target}...")
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                risk = "HIGH" if port in RISKY_PORTS else "LOW"
                open_ports.append({
                    "port": port,
                    "service": service,
                    "risk": risk
                })
                logger.info(f"Port {port} ({service}) OPEN - Risk: {risk}")
            sock.close()
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")
    return open_ports

def check_ssl(target):
    logger.info(f"Checking SSL/TLS on {target}...")
    result = {"ssl_enabled": False, "issues": []}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=target) as s:
            s.settimeout(3)
            s.connect((target, 443))
            cert = s.getpeercert()
            expire_date = datetime.datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.now()).days
            result["ssl_enabled"] = True
            result["expires_in_days"] = days_left
            if days_left < 30:
                result["issues"].append(
                    f"Certificate expires in {days_left} days!")
            logger.info(f"SSL OK - Expires in {days_left} days")
    except Exception as e:
        result["issues"].append(f"SSL check failed: {str(e)}")
        logger.warning(f"SSL issue: {e}")
    return result

def generate_report(target, ports, ssl_result):
    report = {
        "target": target,
        "scan_time": datetime.datetime.now().isoformat(),
        "open_ports": ports,
        "ssl_check": ssl_result,
        "high_risk_ports": [
            p for p in ports if p["risk"] == "HIGH"
        ],
        "summary": {
            "total_open_ports": len(ports),
            "high_risk_count": len(
                [p for p in ports if p["risk"] == "HIGH"]),
            "ssl_issues": len(ssl_result.get("issues", []))
        }
    }
    filename = f"security_report_{target}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f"Report saved to {filename}")
    return report

print(f"{'='*50}")
print(f"  Security Audit Tool")
print(f"  Target: {target}")
print(f"  Time: {datetime.datetime.now()}")
print(f"{'='*50}")

ports = scan_ports(target)
ssl_result = check_ssl(target)
report = generate_report(target, ports, ssl_result)

print(f"{'='*50}")
print(f"  AUDIT SUMMARY")
print(f"{'='*50}")
print(f"  Open Ports : {report['summary']['total_open_ports']}")
print(f"  High Risk  : {report['summary']['high_risk_count']}")
print(f"  SSL Issues : {report['summary']['ssl_issues']}")
print(f"{'='*50}")