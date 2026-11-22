"""FastAPI Backend pentru SSH/Telnet Honeypot.

Oferă endpoint-uri REST pentru statistici și export JSON.
"""

from fastapi import FastAPI, Response

from src.storage import db

app = FastAPI(
    title="SSH/Telnet Honeypot API",
    description="API pentru monitorizarea și analiza atacurilor captate în honeypot.",
    version="1.0.0",
)


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
    """Exportă toate logurile în format JSON.

    Poate fi descărcat direct ca fișier atașat de către administrator.
    """
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

    # Serializare manuală pentru a gestiona obiectele de tip datetime din MySQL
    import json
    from datetime import datetime

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