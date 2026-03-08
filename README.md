# Network Traffic Analysis System

A REST-based backend to ingest, store, and analyze network traffic logs with rule-based anomaly detection.

**Stack:** Python · FastAPI · SQLAlchemy · SQLite (swap to MySQL in one line) · Pydantic

---

## Quick Start (VS Code)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the server
```bash
uvicorn app.main:app --reload
```

### 3. Open the dashboard
Visit → http://127.0.0.1:8000

### 4. Seed sample data (optional)
In a separate terminal:
```bash
python seed_data.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/traffic/ingest` | Ingest a single log |
| POST | `/api/traffic/ingest/bulk` | Ingest up to 1000 logs |
| GET  | `/api/traffic/` | List logs (filterable) |
| GET  | `/api/traffic/{id}` | Get log by ID |
| DELETE | `/api/traffic/{id}` | Delete a log |
| GET  | `/api/alerts/` | List alerts |
| PATCH | `/api/alerts/{id}/resolve` | Resolve an alert |
| GET  | `/api/stats/` | Aggregate stats |

Interactive docs → http://127.0.0.1:8000/docs

---

## Anomaly Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `HIGH_DATA_TRANSFER` | Transfer > 100 MB | High |
| `ELEVATED_DATA_TRANSFER` | Transfer > 10 MB | Medium |
| `SUSPICIOUS_PORT` | Dest port in {22,23,3389,4444,445,...} | Medium–Critical |
| `MALICIOUS_SOURCE_IP` | IP matches threat-intel list | Critical |
| `BLOCKED_TRAFFIC_LOGGED` | action = "block" | Low |
| `BURST_TRAFFIC` | >1 MB in <1 sec | High |
| `PLAINTEXT_ADMIN_PROTOCOL` | Telnet (port 23) | High |

---

## Switch to MySQL

In `.env` or your shell:
```
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/network_traffic
```
Then uncomment `pymysql` in `requirements.txt` and `pip install pymysql`.

---

## Project Structure
```
network-traffic-analyzer/
├── app/
│   ├── main.py          # FastAPI app + middleware
│   ├── database.py      # SQLAlchemy engine + session
│   ├── models.py        # DB models (TrafficLog, SecurityAlert)
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── detection.py     # Rule-based anomaly detection engine
│   └── routers/
│       ├── traffic.py   # /api/traffic endpoints
│       ├── alerts.py    # /api/alerts endpoints
│       └── stats.py     # /api/stats endpoint
├── static/
│   └── dashboard.html   # Browser dashboard (auto-served)
├── seed_data.py         # Populate DB with sample traffic
├── requirements.txt
└── README.md
```
