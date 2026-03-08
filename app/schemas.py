from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
import ipaddress


# ─── Traffic ──────────────────────────────────────────────────────────────────

class TrafficLogCreate(BaseModel):
    source_ip:    str   = Field(..., example="192.168.1.10")
    dest_ip:      str   = Field(..., example="10.0.0.5")
    source_port:  int   = Field(..., ge=0, le=65535)
    dest_port:    int   = Field(..., ge=0, le=65535)
    protocol:     str   = Field(..., example="TCP")
    bytes_sent:   float = Field(..., ge=0)
    bytes_recv:   float = Field(..., ge=0)
    duration_sec: Optional[float] = None
    action:       str   = Field(default="allow", example="allow")

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        allowed = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"}
        if v.upper() not in allowed:
            raise ValueError(f"Protocol must be one of {allowed}")
        return v.upper()

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        if v.lower() not in {"allow", "block"}:
            raise ValueError("Action must be 'allow' or 'block'")
        return v.lower()


class TrafficLogResponse(TrafficLogCreate):
    id:         int
    timestamp:  datetime
    flagged:    bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TrafficLogBulkCreate(BaseModel):
    logs: List[TrafficLogCreate] = Field(..., min_length=1, max_length=1000)


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    id:              int
    traffic_log_id:  Optional[int]
    alert_type:      str
    severity:        str
    source_ip:       str
    dest_ip:         str
    dest_port:       Optional[int]
    description:     Optional[str]
    resolved:        bool
    created_at:      datetime

    model_config = {"from_attributes": True}


# ─── Stats ────────────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total_logs:       int
    flagged_logs:     int
    total_alerts:     int
    unresolved_alerts:int
    top_source_ips:   List[dict]
    top_dest_ports:   List[dict]
    protocol_breakdown: List[dict]
