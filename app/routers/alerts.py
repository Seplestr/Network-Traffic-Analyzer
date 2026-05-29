from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional

from app.database import get_db
from app.models import SecurityAlert
from app.schemas import AlertResponse

router = APIRouter()


@router.get("/", response_model=List[AlertResponse], summary="List security alerts")
def list_alerts(
    skip:       int  = Query(0, ge=0),
    limit:      int  = Query(50, ge=1, le=500),
    severity:   Optional[str]  = Query(None, description="low | medium | high | critical"),
    resolved:   Optional[bool] = Query(None),
    alert_type: Optional[str]  = Query(None),
    db: Session = Depends(get_db),
):
    """Return paginated security alerts with optional severity / resolved filters."""
    q = db.query(SecurityAlert)
    if severity:
        q = q.filter(SecurityAlert.severity == severity.lower())
    if resolved is not None:
        q = q.filter(SecurityAlert.resolved == resolved)
    if alert_type:
        q = q.filter(SecurityAlert.alert_type == alert_type.upper())
    return q.order_by(desc(SecurityAlert.created_at)).offset(skip).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertResponse, summary="Get alert by ID")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/resolve", response_model=AlertResponse,
              summary="Mark alert as resolved")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.resolved = True
    
    # ─── ACTIVE DEFENSIVE MITIGATION ───
    # Dynamically inject an active firewall block policy matching this threat trigger
    from app.models import FirewallRule, TrafficLog
    
    rule_type = None
    rule_value = None
    
    # Inspect threat type
    if alert.alert_type in ("SUSPICIOUS_PORT", "PLAINTEXT_ADMIN_PROTOCOL") and alert.dest_port:
        rule_type = "port"
        rule_value = str(alert.dest_port)
    elif alert.alert_type == "MALICIOUS_SOURCE_IP":
        rule_type = "ip"
        rule_value = alert.source_ip
    else:
        # Fallback: Check if there's an executable we can block
        if alert.traffic_log_id:
            log = db.query(TrafficLog).filter(TrafficLog.id == alert.traffic_log_id).first()
            if log and log.app_name and log.app_name not in ("SYSTEM", "UNKNOWN", "scapy_sniffer"):
                rule_type = "app"
                rule_value = log.app_name
                
        # If no specific application, block the target source IP address
        if not rule_type or not rule_value:
            rule_type = "ip"
            rule_value = alert.source_ip
            
    if rule_type and rule_value:
        val_clean = rule_value.strip()
        # Verify duplicate rule doesn't exist
        existing = (
            db.query(FirewallRule)
            .filter(
                FirewallRule.rule_type == rule_type,
                FirewallRule.value == val_clean
            )
            .first()
        )
        if not existing:
            db_rule = FirewallRule(
                rule_type=rule_type,
                value=val_clean,
                action="block"
            )
            db.add(db_rule)

    db.commit()
    db.refresh(alert)
    return alert

