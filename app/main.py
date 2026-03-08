from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db
from app.routers import traffic, alerts, stats
import os

app = FastAPI(
    title="Network Traffic Analysis System",
    description="REST-based backend to process network traffic logs and detect anomalies",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for the dashboard
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the dashboard UI"""
    html_path = os.path.join(os.path.dirname(__file__), "..", "static", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Network Traffic Analysis System API</h1><p>Visit /docs for API documentation.</p>")

app.include_router(traffic.router, prefix="/api/traffic", tags=["Traffic Logs"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Security Alerts"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
