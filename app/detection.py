"""
Rule-based anomaly detection engine.
Checks each traffic log against a set of rules and returns a list of alerts.
"""
from dataclasses import dataclass
from typing import List, Optional

# ─── Thresholds ───────────────────────────────────────────────────────────────
HIGH_TRANSFER_BYTES   = 100 * 1024 * 1024   # 100 MB
MEDIUM_TRANSFER_BYTES =  10 * 1024 * 1024   # 10 MB

# Ports commonly associated with attacks / sensitive services
SUSPICIOUS_PORTS = {
    22, 23, 3389, 445, 135, 139,    # SSH, Telnet, RDP, SMB
    4444, 5555, 6666, 7777, 8888,   # Common reverse-shell ports
    1433, 3306, 5432, 27017,        # DB ports exposed to internet
    6379, 11211,                     # Redis, Memcached
}

KNOWN_MALICIOUS_IPS = {
    "10.0.0.99",    # placeholder — replace with real threat-intel feed
}


@dataclass
class DetectedAlert:
    alert_type:  str
    severity:    str
    description: str


def analyze(
    source_ip: str,
    dest_ip: str,
    source_port: int,
    dest_port: int,
    protocol: str,
    bytes_sent: float,
    bytes_recv: float,
    duration_sec: Optional[float],
    action: str,
) -> List[DetectedAlert]:
    """
    Run all detection rules against a single traffic record.
    Returns a (possibly empty) list of DetectedAlert objects.
    """
    alerts: List[DetectedAlert] = []

    # Rule 1 – High data transfer
    total_bytes = bytes_sent + bytes_recv
    if total_bytes >= HIGH_TRANSFER_BYTES:
        alerts.append(DetectedAlert(
            alert_type="HIGH_DATA_TRANSFER",
            severity="high",
            description=(
                f"Abnormally large transfer: {total_bytes / (1024*1024):.1f} MB "
                f"between {source_ip} → {dest_ip}"
            ),
        ))
    elif total_bytes >= MEDIUM_TRANSFER_BYTES:
        alerts.append(DetectedAlert(
            alert_type="ELEVATED_DATA_TRANSFER",
            severity="medium",
            description=(
                f"Elevated transfer: {total_bytes / (1024*1024):.1f} MB "
                f"between {source_ip} → {dest_ip}"
            ),
        ))

    # Rule 2 – Suspicious destination port
    if dest_port in SUSPICIOUS_PORTS:
        severity = "critical" if dest_port in {4444, 5555, 6666, 7777} else "medium"
        alerts.append(DetectedAlert(
            alert_type="SUSPICIOUS_PORT",
            severity=severity,
            description=f"Traffic to sensitive/suspicious port {dest_port} from {source_ip}",
        ))

    # Rule 3 – Known malicious source IP
    if source_ip in KNOWN_MALICIOUS_IPS:
        alerts.append(DetectedAlert(
            alert_type="MALICIOUS_SOURCE_IP",
            severity="critical",
            description=f"Traffic from known malicious IP: {source_ip}",
        ))

    # Rule 4 – Blocked traffic still reaching detector (WAF/firewall bypass indicator)
    if action == "block":
        alerts.append(DetectedAlert(
            alert_type="BLOCKED_TRAFFIC_LOGGED",
            severity="low",
            description=f"Blocked connection attempt from {source_ip}:{source_port} → {dest_ip}:{dest_port}",
        ))

    # Rule 5 – Extremely short high-volume burst (possible DoS probe)
    if duration_sec is not None and duration_sec < 1 and total_bytes > 1 * 1024 * 1024:
        alerts.append(DetectedAlert(
            alert_type="BURST_TRAFFIC",
            severity="high",
            description=(
                f"High-volume burst ({total_bytes/1024:.0f} KB) in {duration_sec:.2f}s "
                f"from {source_ip}"
            ),
        ))

    # Rule 6 – Telnet / plaintext admin protocols
    if dest_port == 23:
        alerts.append(DetectedAlert(
            alert_type="PLAINTEXT_ADMIN_PROTOCOL",
            severity="high",
            description=f"Telnet connection detected from {source_ip} to {dest_ip}",
        ))

    return alerts
