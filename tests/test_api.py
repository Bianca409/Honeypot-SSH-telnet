import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.web.app import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "honeypot-backend"}


def test_get_stats_endpoint():
    mock_summary = {
        "total_attacks": 10,
        "ssh_attacks": 7,
        "telnet_attacks": 3,
        "shell_commands": 4,
    }
    mock_passwords = [{"password": "admin", "count": 5}]
    mock_ips = [{"source_ip": "192.168.1.100", "count": 6}]

    with (
        patch("src.storage.db.get_summary_stats", return_value=mock_summary),
        patch("src.storage.db.get_top_passwords", return_value=mock_passwords),
        patch("src.storage.db.get_top_ips", return_value=mock_ips),
    ):
        response = client.get("/api/stats")

    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["total_attacks"] == 10
    assert data["top_passwords"][0]["password"] == "admin"
    assert data["top_ips"][0]["source_ip"] == "192.168.1.100"


def test_get_recent_attempts_endpoint():
    sample_attempts = [{"id": 1, "protocol": "SSH", "username": "root"}]
    with patch(
        "src.storage.db.get_recent_auth_attempts", return_value=sample_attempts
    ):
        response = client.get("/api/attempts?limit=5")

    assert response.status_code == 200
    assert response.json() == {"attempts": sample_attempts}


def test_export_json_endpoint():
    mock_summary = {"total_attacks": 1, "ssh_attacks": 1, "telnet_attacks": 0, "shell_commands": 0}
    with (
        patch("src.storage.db.get_summary_stats", return_value=mock_summary),
        patch("src.storage.db.get_top_passwords", return_value=[]),
        patch("src.storage.db.get_top_ips", return_value=[]),
        patch("src.storage.db.get_recent_auth_attempts", return_value=[]),
        patch("src.storage.db.get_recent_shell_commands", return_value=[]),
    ):
        response = client.get("/api/export")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "attachment; filename=honeypot_export.json" in response.headers["content-disposition"]

    data = json.loads(response.text)
    assert "export_metadata" in data
    assert data["export_metadata"]["service"] == "SSH/Telnet Honeypot"
    assert "summary" in data


def test_dashboard_page_renders_html():
    mock_summary = {
        "total_attacks": 2,
        "ssh_attacks": 1,
        "telnet_attacks": 1,
        "shell_commands": 1,
    }
    with (
        patch("src.storage.db.get_summary_stats", return_value=mock_summary),
        patch("src.storage.db.get_top_passwords", return_value=[]),
        patch("src.storage.db.get_top_ips", return_value=[]),
        patch("src.storage.db.get_recent_auth_attempts", return_value=[]),
        patch("src.storage.db.get_recent_shell_commands", return_value=[]),
    ):
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SSH &amp; Telnet Honeypot Dashboard" in response.text
