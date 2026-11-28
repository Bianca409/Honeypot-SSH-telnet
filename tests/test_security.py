from unittest.mock import patch

from fastapi.testclient import TestClient

from src.web.app import app

client = TestClient(app)


def test_dashboard_escapes_xss_payloads():
    xss_payload = "<script>alert(1)</script>"
    mock_summary = {
        "total_attacks": 1,
        "ssh_attacks": 1,
        "telnet_attacks": 0,
        "shell_commands": 1,
    }
    mock_passwords = [{"password": xss_payload, "count": 3}]
    mock_ips = [{"source_ip": "10.0.0.5", "count": 3}]
    mock_attempts = [
        {
            "timestamp": "2026-11-28 12:00:00",
            "protocol": "SSH",
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "username": f"admin{xss_payload}",
            "password": xss_payload,
            "status": "REJECTED",
        }
    ]
    mock_commands = [
        {
            "timestamp": "2026-11-28 12:01:00",
            "session_id": "sess-xss",
            "source_ip": "10.0.0.5",
            "command": f"echo {xss_payload}",
        }
    ]

    with (
        patch("src.storage.db.get_summary_stats", return_value=mock_summary),
        patch("src.storage.db.get_top_passwords", return_value=mock_passwords),
        patch("src.storage.db.get_top_ips", return_value=mock_ips),
        patch("src.storage.db.get_recent_auth_attempts", return_value=mock_attempts),
        patch("src.storage.db.get_recent_shell_commands", return_value=mock_commands),
    ):
        response = client.get("/")

    assert response.status_code == 200
    assert xss_payload not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_security_headers_present():
    response = client.get("/api/health")

    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_api_pagination_and_limit_validation():
    assert client.get("/api/attempts?limit=0").status_code == 422
    assert client.get("/api/attempts?limit=201").status_code == 422
    assert client.get("/api/attempts?offset=-1").status_code == 422

    assert client.get("/api/commands?limit=0").status_code == 422
    assert client.get("/api/commands?limit=201").status_code == 422
    assert client.get("/api/commands?offset=-1").status_code == 422

    assert client.get("/api/export?limit=501").status_code == 422

    with patch("src.storage.db.get_recent_auth_attempts", return_value=[]) as mock_attempts:
        resp = client.get("/api/attempts?limit=10&offset=20")
        assert resp.status_code == 200
        mock_attempts.assert_called_once_with(limit=10, offset=20)
