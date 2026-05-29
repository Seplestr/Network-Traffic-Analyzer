import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routers import traffic, alerts, stats, firewall
from app.ws_manager import connected_clients

import os

app = FastAPI(
    title="Network Traffic Analysis System",
    description="REST-based backend to process network traffic logs and detect anomalies",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# STATIC FILES
static_dir = os.path.join(
    os.path.dirname(__file__),
    "..",
    "static"
)

if os.path.exists(static_dir):
    app.mount(
        "/static",
        StaticFiles(directory=static_dir),
        name="static"
    )

# STARTUP
@app.on_event("startup")
async def startup():
    init_db()
    print("[SUCCESS] Database tables created.")

# DASHBOARD PAGE
@app.get("/", response_class=HTMLResponse)
async def root():

    html_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "static",
        "dashboard.html"
    )

    if os.path.exists(html_path):
        with open(html_path, encoding="utf-8") as f:
            return f.read()

    return HTMLResponse(
        "<h1>Dashboard not found</h1>"
    )

# SECURITY CENTER PAGE
@app.get("/security-center", response_class=HTMLResponse)
async def security_center_page():
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "static",
        "pages",
        "security_center.html"
    )
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Security Center page not found</h1>")


# FIREWALL CONSOLE PAGE
@app.get("/firewall-console", response_class=HTMLResponse)
async def firewall_console_page():
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "static",
        "pages",
        "firewall_console.html"
    )
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Firewall Console page not found</h1>")


# API ROUTERS
app.include_router(
    traffic.router,
    prefix="/api/traffic",
    tags=["Traffic Logs"]
)

app.include_router(
    alerts.router,
    prefix="/api/alerts",
    tags=["Security Alerts"]
)

app.include_router(
    stats.router,
    prefix="/api/stats",
    tags=["Statistics"]
)

app.include_router(
    firewall.router,
    prefix="/api/firewall",
    tags=["Firewall Rules"]
)

# WEBSOCKET
@app.websocket("/ws/live-traffic")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    connected_clients.append(websocket)

    print("[SUCCESS] WebSocket connected")

    try:
        while True:
            await websocket.receive_text()

    except Exception as e:
        print("[ERROR] WebSocket disconnected:", e)

    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)