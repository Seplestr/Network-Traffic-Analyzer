from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from datetime import datetime
from app.database import Base


class TrafficLog(Base):
    """Stores raw ingested network traffic records."""
    __tablename__ = "traffic_logs"

    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip     = Column(String(45), nullable=False, index=True)
    dest_ip       = Column(String(45), nullable=False, index=True)
    source_port   = Column(Integer, nullable=False)
    dest_port     = Column(Integer, nullable=False, index=True)
    protocol      = Column(String(10), nullable=False)       # TCP / UDP / ICMP
    bytes_sent    = Column(Float, nullable=False, default=0)
    bytes_recv    = Column(Float, nullable=False, default=0)
    duration_sec  = Column(Float, nullable=True)
    action        = Column(String(20), default="allow")      # allow / block
    app_name      = Column(String(100), nullable=True, default="SYSTEM")
    flagged       = Column(Boolean, default=False, index=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


class SecurityAlert(Base):
    """Stores anomaly-detection results linked to a traffic log."""
    __tablename__ = "security_alerts"

    id            = Column(Integer, primary_key=True, index=True)
    traffic_log_id= Column(Integer, nullable=True, index=True)
    alert_type    = Column(String(60), nullable=False)       # e.g. HIGH_DATA_TRANSFER
    severity      = Column(String(20), nullable=False)       # low / medium / high / critical
    source_ip     = Column(String(45), nullable=False)
    dest_ip       = Column(String(45), nullable=False)
    dest_port     = Column(Integer, nullable=True)
    description   = Column(Text, nullable=True)
    resolved      = Column(Boolean, default=False, index=True)
    created_at    = Column(DateTime, default=datetime.utcnow, index=True)


class FirewallRule(Base):
    """Stores custom user firewall block policies."""
    __tablename__ = "firewall_rules"

    id            = Column(Integer, primary_key=True, index=True)
    rule_type     = Column(String(20), nullable=False)       # "ip" | "port" | "app"
    value         = Column(String(100), nullable=False, index=True)
    action        = Column(String(20), default="block")      # "allow" | "block"
    created_at    = Column(DateTime, default=datetime.utcnow)

