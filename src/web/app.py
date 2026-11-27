"""FastAPI Backend și Dashboard Web pentru SSH/Telnet Honeypot."""

import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.storage import db

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="SSH/Telnet Honeypot API",
    description="API și Dashboard pentru monitorizarea atacurilor din honeypot.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    """Randează pagina principală a Dashboard-ului Web (cu auto-escaping XSS)."""
    context = {
        "request": request,
        "summary": db.get_summary_stats(),
        "top_passwords": db.get_top_passwords(limit=10),
        "top_ips": db.get_top_ips(limit=10),
        "recent_attempts": db.get_recent_auth_attempts(limit=50),
        "recent_commands": db.get_recent_shell_commands(limit=50),
    }
    return templates.TemplateResponse(request, "index.html", context)


@app.get("/api/health")
def health_check():
    """Verifică starea serverului web."""
    return {"status": "ok", "service": "honeypot-backend"}


@app.get("/api/stats")
def get_stats():
    """Returnează statisticile agregate (top parole, top IP-uri, totaluri)."""
    return {
        "summary": db.get_summary_stats(),
        "top_passwords": db.get_top_passwords(limit=10),
        "top_ips": db.get_top_ips(limit=10),
    }


@app.get("/api/attempts")
def get_recent_attempts(limit: int = 50):
    """Returnează cele mai recente tentative de autentificare captate."""
    return {"attempts": db.get_recent_auth_attempts(limit=limit)}


@app.get("/api/commands")
def get_recent_commands(limit: int = 50):
    """Returnează comenzile rulate de atacatori în fake shell."""
    return {"commands": db.get_recent_shell_commands(limit=limit)}


@app.get("/api/export")
def export_json():
    """Exportă toate logurile în format JSON."""
    export_data = {
        "export_metadata": {
            "service": "SSH/Telnet Honeypot",
            "version": "1.0",
        },
        "summary": db.get_summary_stats(),
        "top_passwords": db.get_top_passwords(limit=20),
        "top_ips": db.get_top_ips(limit=20),
        "recent_auth_attempts": db.get_recent_auth_attempts(limit=200),
        "recent_shell_commands": db.get_recent_shell_commands(limit=200),
    }

    def json_serial(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Tip neserializabil: {type(obj)}")

    json_content = json.dumps(export_data, indent=2, default=json_serial)

    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=honeypot_export.json"},
    )