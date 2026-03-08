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
    db.commit()
    db.refresh(alert)
    return alert
