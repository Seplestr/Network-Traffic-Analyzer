from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import FirewallRule
from app.schemas import FirewallRuleCreate, FirewallRuleResponse

router = APIRouter()


@router.get("/", response_model=List[FirewallRuleResponse], summary="List all active firewall rules")
def list_rules(db: Session = Depends(get_db)):
    """Return all active firewall blocking policies."""
    return db.query(FirewallRule).order_by(FirewallRule.created_at.desc()).all()


@router.post("/", response_model=FirewallRuleResponse, status_code=201, summary="Create a new firewall rule")
def create_rule(rule: FirewallRuleCreate, db: Session = Depends(get_db)):
    """Add a new dynamic block policy for a process name, port, or IP address."""
    val_clean = rule.value.strip()
    
    # Check if duplicate rule exists
    existing = (
        db.query(FirewallRule)
        .filter(
            FirewallRule.rule_type == rule.rule_type,
            FirewallRule.value == val_clean
        )
        .first()
    )
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Firewall block policy already exists for {rule.rule_type}: '{val_clean}'"
        )

    db_rule = FirewallRule(
        rule_type=rule.rule_type,
        value=val_clean,
        action=rule.action
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.delete("/{rule_id}", status_code=204, summary="Delete an active firewall rule")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """Revoke an active dynamic blocking policy."""
    db_rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(
            status_code=404,
            detail="Firewall block policy not found"
        )
    db.delete(db_rule)
    db.commit()
    return None
