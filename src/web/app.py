"""FastAPI Backend și Dashboard Web pentru SSH/Telnet Honeypot."""

import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Query, Request, Response
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


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Adaugă headere CSP și protecție anti-XSS/clickjacking pe toate răspunsurile."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'none'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


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
def get_recent_attempts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Returnează cele mai recente tentative de autentificare captate (paginate)."""
    return {"attempts": db.get_recent_auth_attempts(limit=limit, offset=offset)}


@app.get("/api/commands")
def get_recent_commands(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Returnează comenzile rulate de atacatori în fake shell (paginate)."""
    return {"commands": db.get_recent_shell_commands(limit=limit, offset=offset)}


@app.get("/api/export")
def export_json(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Exportă logurile în format JSON (cu limită și paginare)."""
    export_data = {
        "export_metadata": {
            "service": "SSH/Telnet Honeypot",
            "version": "1.0",
            "limit": limit,
            "offset": offset,
        },
        "summary": db.get_summary_stats(),
        "top_passwords": db.get_top_passwords(limit=20),
        "top_ips": db.get_top_ips(limit=20),
        "recent_auth_attempts": db.get_recent_auth_attempts(limit=limit, offset=offset),
        "recent_shell_commands": db.get_recent_shell_commands(limit=limit, offset=offset),
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