from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from app.ws_manager import connected_clients

import json

from app.database import get_db
from app.models import TrafficLog, SecurityAlert
from app.schemas import (
    TrafficLogCreate,
    TrafficLogResponse,
    TrafficLogBulkCreate
)
from app import detection

router = APIRouter()


# =========================
# CORE INGEST FUNCTION
# =========================
def _ingest_log(log_data: TrafficLogCreate, db: Session):
    # Check if this traffic matches any custom dynamic firewall rules
    from app.models import FirewallRule
    rules = db.query(FirewallRule).all()
    
    custom_blocked = False
    block_reason = ""
    for r in rules:
        if r.action == "block":
            r_val = r.value.strip()
            # Match IP
            if r.rule_type == "ip":
                if log_data.source_ip == r_val or log_data.dest_ip == r_val:
                    custom_blocked = True
                    block_reason = f"Blacklisted IP '{r_val}'"
                    break
            # Match Port
            elif r.rule_type == "port":
                try:
                    p_val = int(r_val)
                    if log_data.source_port == p_val or log_data.dest_port == p_val:
                        custom_blocked = True
                        block_reason = f"Restricted Port '{r_val}'"
                        break
                except ValueError:
                    pass
            # Match Application
            elif r.rule_type == "app":
                if log_data.app_name and r_val.lower() in log_data.app_name.lower():
                    custom_blocked = True
                    block_reason = f"Blocked Process '{r_val}'"
                    break

    detected = detection.analyze(
        source_ip=log_data.source_ip,
        dest_ip=log_data.dest_ip,
        source_port=log_data.source_port,
        dest_port=log_data.dest_port,
        protocol=log_data.protocol,
        bytes_sent=log_data.bytes_sent,
        bytes_recv=log_data.bytes_recv,
        duration_sec=log_data.duration_sec,
        action="block" if custom_blocked else log_data.action,
    )

    # Inject firewall block alert
    if custom_blocked:
        from app.detection import DetectedAlert
        has_block_alert = any(a.alert_type in ("BLOCKED_TRAFFIC_LOGGED", "FIREWALL_POLICY_BLOCK") for a in detected)
        if not has_block_alert:
            detected.append(DetectedAlert(
                alert_type="FIREWALL_POLICY_BLOCK",
                severity="critical",
                description=f"Active Firewall block enforced: {block_reason}"
            ))

    flagged = len(detected) > 0
    action = "block" if (flagged or custom_blocked) else log_data.action

    log_dict = log_data.model_dump()
    log_dict["action"] = action
    log_dict["flagged"] = flagged

    db_log = TrafficLog(**log_dict)

    db.add(db_log)
    db.flush()

    # SAVE ALERTS
    for alert in detected:

        db_alert = SecurityAlert(
            traffic_log_id=db_log.id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            source_ip=log_data.source_ip,
            dest_ip=log_data.dest_ip,
            dest_port=log_data.dest_port,
            description=alert.description,
        )

        db.add(db_alert)

    db.commit()
    db.refresh(db_log)

    return db_log



# =========================
# INGEST SINGLE LOG
# =========================
@router.post(
    "/ingest",
    response_model=TrafficLogResponse,
    status_code=201,
    summary="Ingest a single traffic log"
)
async def ingest_log(
    log: TrafficLogCreate,
    db: Session = Depends(get_db)
):

    db_log = _ingest_log(log, db)

    # LIVE WEBSOCKET PAYLOAD
    payload = {
        "source_ip": db_log.source_ip,
        "dest_ip": db_log.dest_ip,
        "source_port": db_log.source_port,
        "dest_port": db_log.dest_port,
        "protocol": db_log.protocol,
        "bytes_sent": db_log.bytes_sent,
        "flagged": db_log.flagged,
        "app_name": db_log.app_name,
        "action": db_log.action,
    }

    disconnected = []

    for ws in connected_clients:

        try:
            await ws.send_text(json.dumps(payload))

        except:
            disconnected.append(ws)

    for ws in disconnected:

        if ws in connected_clients:
            connected_clients.remove(ws)

    return db_log


# =========================
# BULK INGEST
# =========================
@router.post(
    "/ingest/bulk",
    status_code=201,
    summary="Ingest multiple traffic logs"
)
def ingest_bulk(
    payload: TrafficLogBulkCreate,
    db: Session = Depends(get_db)
):

    results = []

    for log_data in payload.logs:

        db_log = _ingest_log(log_data, db)

        results.append({
            "id": db_log.id,
            "flagged": db_log.flagged
        })

    return {
        "ingested": len(results),
        "results": results
    }


# =========================
# LIST LOGS
# =========================
@router.get(
    "/",
    response_model=List[TrafficLogResponse],
    summary="List traffic logs"
)
def list_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    flagged: Optional[bool] = Query(None),
    source_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):

    q = db.query(TrafficLog)

    if flagged is not None:
        q = q.filter(TrafficLog.flagged == flagged)

    if source_ip:
        q = q.filter(TrafficLog.source_ip == source_ip)

    if protocol:
        q = q.filter(TrafficLog.protocol == protocol.upper())

    return (
        q.order_by(desc(TrafficLog.timestamp))
        .offset(skip)
        .limit(limit)
        .all()
    )


# =========================
# GET SINGLE LOG
# =========================
@router.get(
    "/{log_id}",
    response_model=TrafficLogResponse,
    summary="Get traffic log"
)
def get_log(
    log_id: int,
    db: Session = Depends(get_db)
):

    log = (
        db.query(TrafficLog)
        .filter(TrafficLog.id == log_id)
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="Traffic log not found"
        )

    return log


# =========================
# DELETE LOG
# =========================
@router.delete(
    "/{log_id}",
    status_code=204,
    summary="Delete traffic log"
)
def delete_log(
    log_id: int,
    db: Session = Depends(get_db)
):

    log = (
        db.query(TrafficLog)
        .filter(TrafficLog.id == log_id)
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="Traffic log not found"
        )

    db.delete(log)
    db.commit()