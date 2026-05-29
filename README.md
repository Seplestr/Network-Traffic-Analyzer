# NetWatch: Interactive PC Firewall & Network SOC Console

A production-grade, high-fidelity **Personal Desktop Security & Dynamic Firewall Console** that sniffs active Windows host network connections in real-time, maps connection sockets directly to local executable modules (e.g. `chrome.exe`, `python.exe`), and enforces automated firewall blocks dynamically.

**Stack:** Python · FastAPI · SQLAlchemy · MySQL (PyMySQL) · Pydantic · Scapy · psutil · Chart.js

---

## 📊 Visual Showcases (UI Screenshots)

### 1. SOC Dashboard (Real-Time Ingestion & Telemetry Analytics)
![SOC Dashboard](screenshots/dashboard_light_theme.png)

### 2. Security Operations & Response Center (Active Threat Containment & CISA Bulletins)
![Security Center](screenshots/security_center_alerts.png)

### 3. Firewall Operations Console (Full-Width Sockets Flow & Hover Hex Decoder)
![Firewall Console](screenshots/firewall_console_flow.png)

---

## 🚀 Architectural Overview

NetWatch operates as a lightweight, reactive **SOAR (Security Orchestration, Automation, and Response)** platform:
1. **Live Sniffer Daemon (`live_sniffer.py`)**: Intercepts active network connections on your actual Windows host via Scapy raw packets or psutil socket-to-process PID mapping, immediately POSTing socket records to the backend.
2. **Ingestion & Policy Interceptor (`app/routers/traffic.py`)**: Evaluates incoming logs against dynamic database firewall policies in real-time. Matches are instantly flagged as `BLOCK` events and generate critical security alerts.
3. **Decoupled Unified Portal (`static/`)**: A highly polished administrative Light SOC Console separating telemetries, incident mitigation boards, and full-screen traffic flow streams.

---

## ⚡ Quick Start

### 1. Configure MySQL Database Connection
Set your MySQL server connection string in your `.env` file:
```env
DATABASE_URL=mysql+pymysql://root:mysql@localhost:3306/network_traffic
```

### 2. Start the FastAPI Web Server
Launch the server with the auto-reload flag:
```bash
uv run uvicorn app.main:app --port 8000 --reload
```
*(On startup, NetWatch will automatically initialize all required database tables including `traffic_logs`, `security_alerts`, and `firewall_rules`.)*

### 3. Start the Live Host Sniffer Daemon
In a separate terminal window, launch the tracker:
```bash
uv run live_sniffer.py
```
*(The sniffer will query active host PIDs and stream connections dynamically.)*

### 4. Access the SOC Console Portal
Open your browser and navigate to:
👉 **SOC Dashboard**: http://127.0.0.1:8000  
👉 **Security Center**: http://127.0.0.1:8000/security-center  
👉 **Firewall Console**: http://127.0.0.1:8000/firewall-console  

---

## 🛡️ Core API Endpoints

### Traffic Logs
* `POST /api/traffic/ingest` - Ingest a single captured network socket log.
* `POST /api/traffic/ingest/bulk` - Ingest up to 1000 logs simultaneously.
* `GET /api/traffic/` - Query paginated captures (filterable by protocol, status, IP).

### Dynamic Firewall Policies
* `GET /api/firewall/` - List all active dynamic database block policies.
* `POST /api/firewall/` - Create a new block rule (Executable app name, target IP, or Port).
* `DELETE /api/firewall/{rule_id}` - Revoke an active block policy instantly.

### Security Incidents & Threat Intel
* `GET /api/alerts/` - Query recorded anomaly logs requiring analyst response.
* `PATCH /api/alerts/{id}/resolve` - Mark an alert resolved and automatically deploy active firewall containment matching the threat parameters!
* `GET /api/stats/` - Query aggregated volume metrics, protocol share counts, and top sources.
* `GET /api/stats/intel` - Dynamic IRL threat bulletins feed aggregating major zero-day CVE advisories and ransomware campaign bulletins.

---

## 📂 Project Structure

```
network-traffic-analyzer/
├── app/
│   ├── main.py              # Core FastAPI app & page router routes
│   ├── database.py          # SQLAlchemy connection engine
│   ├── models.py            # DB Models (TrafficLog, SecurityAlert, FirewallRule)
│   ├── schemas.py           # Pydantic request & response validators
│   ├── detection.py         # Rule-based anomalies detection engine
│   └── routers/
│       ├── traffic.py       # Live flow ingestion & client WebSocket streams
│       ├── alerts.py        # Mitigate alerts & dynamic defensive containment
│       ├── stats.py         # Telemetry aggregation & IRL CISA Threat feed
│       └── firewall.py      # Dynamic policies registry controls
├── static/
│   ├── dashboard.html       # Visual analytics charts portal
│   ├── css/
│   │   └── dashboard.css    # Unified administrative Light SOC stylesheet
│   ├── js/
│   │   ├── dashboard.js     # Telemetry & volume tables controller
│   │   ├── firewall_console.js # Live WebSocket stream & hex editor highlights
│   │   └── security_center.js  # Incident board & Threat news updates
│   └── pages/
│       ├── firewall_console.html # Wide stream packet flow console
│       └── security_center.html  # Incident mitigation & Threat Hub
├── live_sniffer.py          # Active host Scapy/psutil socket sniffer
├── requirements.txt         # Project package requirements list
└── README.md                # Comprehensive documentation
```
