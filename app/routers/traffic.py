from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime

from app.database import get_db
from app.models import TrafficLog, SecurityAlert
from app.schemas import TrafficLogCreate, TrafficLogResponse, TrafficLogBulkCreate
from app import detection

router = APIRouter()


def _ingest_log(log_data: TrafficLogCreate, db: Session) -> TrafficLog:
    """Core ingestion logic: save log + run detection + save alerts."""
    # 1. Detect anomalies before persisting
    detected = detection.analyze(
        source_ip=log_data.source_ip,
        dest_ip=log_data.dest_ip,
        source_port=log_data.source_port,
        dest_port=log_data.dest_port,
        protocol=log_data.protocol,
        bytes_sent=log_data.bytes_sent,
        bytes_recv=log_data.bytes_recv,
        duration_sec=log_data.duration_sec,
        action=log_data.action,
    )

    flagged = len(detected) > 0

    # 2. Persist traffic log
    db_log = TrafficLog(**log_data.model_dump(), flagged=flagged)
    db.add(db_log)
    db.flush()  # get db_log.id before commit

    # 3. Persist any alerts
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


@router.post("/ingest", response_model=TrafficLogResponse, status_code=201,
             summary="Ingest a single traffic log")
def ingest_log(log: TrafficLogCreate, db: Session = Depends(get_db)):
    """
    Ingest a single network traffic record.
    Runs anomaly detection and stores any triggered alerts automatically.
    """
    return _ingest_log(log, db)


@router.post("/ingest/bulk", summary="Ingest multiple traffic logs at once")
def ingest_bulk(payload: TrafficLogBulkCreate, db: Session = Depends(get_db)):
    """Bulk ingest up to 1000 traffic records in a single request."""
    results = []
    for log_data in payload.logs:
        db_log = _ingest_log(log_data, db)
        results.append({"id": db_log.id, "flagged": db_log.flagged})
    return {"ingested": len(results), "results": results}


@router.get("/", response_model=List[TrafficLogResponse],
            summary="List traffic logs")
def list_logs(
    skip:      int  = Query(0, ge=0),
    limit:     int  = Query(50, ge=1, le=500),
    flagged:   Optional[bool]   = Query(None, description="Filter by flagged status"),
    source_ip: Optional[str]    = Query(None),
    protocol:  Optional[str]    = Query(None),
    db: Session = Depends(get_db),
):
    """Return paginated traffic logs with optional filters."""
    q = db.query(TrafficLog)
    if flagged is not None:
        q = q.filter(TrafficLog.flagged == flagged)
    if source_ip:
        q = q.filter(TrafficLog.source_ip == source_ip)
    if protocol:
        q = q.filter(TrafficLog.protocol == protocol.upper())
    return q.order_by(desc(TrafficLog.timestamp)).offset(skip).limit(limit).all()


@router.get("/{log_id}", response_model=TrafficLogResponse,
            summary="Get a traffic log by ID")
def get_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Traffic log not found")
    return log


@router.delete("/{log_id}", status_code=204, summary="Delete a traffic log")
def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Traffic log not found")
    db.delete(log)
    db.commit()
