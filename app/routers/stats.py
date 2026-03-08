from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import TrafficLog, SecurityAlert
from app.schemas import StatsResponse

router = APIRouter()


@router.get("/", response_model=StatsResponse, summary="System-wide statistics")
def get_stats(db: Session = Depends(get_db)):
    """Aggregate statistics for the dashboard."""
    total_logs        = db.query(func.count(TrafficLog.id)).scalar() or 0
    flagged_logs      = db.query(func.count(TrafficLog.id)).filter(TrafficLog.flagged == True).scalar() or 0
    total_alerts      = db.query(func.count(SecurityAlert.id)).scalar() or 0
    unresolved_alerts = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.resolved == False).scalar() or 0

    # Top 5 source IPs by log count
    top_ips = (
        db.query(TrafficLog.source_ip, func.count(TrafficLog.id).label("count"))
        .group_by(TrafficLog.source_ip)
        .order_by(func.count(TrafficLog.id).desc())
        .limit(5)
        .all()
    )

    # Top 5 destination ports
    top_ports = (
        db.query(TrafficLog.dest_port, func.count(TrafficLog.id).label("count"))
        .group_by(TrafficLog.dest_port)
        .order_by(func.count(TrafficLog.id).desc())
        .limit(5)
        .all()
    )

    # Protocol breakdown
    protocols = (
        db.query(TrafficLog.protocol, func.count(TrafficLog.id).label("count"))
        .group_by(TrafficLog.protocol)
        .order_by(func.count(TrafficLog.id).desc())
        .all()
    )

    return StatsResponse(
        total_logs=total_logs,
        flagged_logs=flagged_logs,
        total_alerts=total_alerts,
        unresolved_alerts=unresolved_alerts,
        top_source_ips=[{"ip": r.source_ip, "count": r.count} for r in top_ips],
        top_dest_ports=[{"port": r.dest_port, "count": r.count} for r in top_ports],
        protocol_breakdown=[{"protocol": r.protocol, "count": r.count} for r in protocols],
    )
