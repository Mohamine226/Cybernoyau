import glob
import os
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from server.app import create_app
from server.service import MonitorService
from cubernoyau.config import settings
from cubernoyau.storage.database import Database


@pytest.fixture()
def service(tmp_path):
    svc = MonitorService(Database(tmp_path / "t.db"), watch_dirs=[])
    yield svc
    svc.stop()
    svc.db.close()


@pytest.fixture()
def client(service):
    with TestClient(create_app(service, autostart=False)) as c:
        yield c


def test_health_status_and_frontend(client):
    assert client.get("/api/health").json()["status"] == "ok"
    status = client.get("/api/status").json()
    assert status["monitor"]["running"] is False
    assert "Mougle Protect" in client.get("/").text
    assert "use strict" in client.get("/static/app.js").text
    assert ":root" in client.get("/static/style.css").text


def test_rejects_foreign_host_header(service):
    with TestClient(create_app(service, autostart=False),
                    base_url="http://evil.example") as c:
        assert c.get("/api/health").status_code == 400


def test_link_scan_creates_alert_then_ack(client):
    body = {"urls": ["http://paypal.com@secure-login.example.tk/verify",
                     "https://docs.python.org/3/"]}
    results = client.post("/api/scan/links", json=body).json()["results"]
    assert [r["assessment"] for r in results] == [
        "RISQUE_ELEVE", "AUCUN_INDICATEUR_DETECTE"]
    assert results[0]["decision"]["automatic_action"] == "aucune"

    alerts = client.get("/api/alerts").json()["alerts"]
    assert len(alerts) == 1 and alerts[0]["source"] == "link"
    alert_id = alerts[0]["id"]
    assert client.post(f"/api/alerts/{alert_id}/ack").json()["acknowledged"]
    assert client.get("/api/alerts?acknowledged=false").json()["alerts"] == []
    assert client.post("/api/alerts/9999/ack").status_code == 404
    assert client.get("/api/status").json()["counts"]["scans"] == 2


def test_link_scan_validation(client):
    assert client.post("/api/scan/links", json={"urls": []}).status_code == 422
    assert client.post("/api/scan/links",
                       json={"urls": ["http://a.com/" + "x" * 3000]}).status_code == 422
    assert client.post("/api/scan/links", json={}).status_code == 422


def test_upload_double_extension_and_temp_cleanup(client):
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "cubernoyau_*")))
    response = client.post("/api/scan/file", files={
        "file": ("facture.pdf.exe", b"pas un vrai programme")})
    assert response.status_code == 200
    data = response.json()
    codes = {i["code"] for i in data["risk_indicators"]}
    assert "MISLEADING_DOUBLE_EXTENSION" in codes
    assert data["assessment"] == "SUSPECT"
    assert data["file_name"] == "facture.pdf.exe"
    assert data["file_path"].startswith("televerse/")
    assert data["executed"] is False
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "cubernoyau_*")))
    assert after == before  # fichier televerse supprime


def test_upload_path_traversal_name_is_neutralised(client):
    data = client.post("/api/scan/file", files={
        "file": ("../../etc/passwd.txt", b"x")}).json()
    assert data["file_name"] == "passwd.txt"


def test_upload_application_and_size_limit(client, monkeypatch):
    pe = bytearray(256)
    pe[0:2] = b"MZ"
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\0\0"
    data = client.post("/api/scan/application",
                       files={"file": ("tool.exe", bytes(pe))}).json()
    assert data["pe_header_valid"] is True
    monkeypatch.setattr(settings, "MAX_UPLOAD_MB", 0.0001)
    assert client.post("/api/scan/file", files={
        "file": ("big.bin", b"x" * 5000)}).status_code == 413


def test_path_scan_directory_file_and_errors(client, tmp_path):
    tmp_path = tmp_path / "cible"  # distinct du dossier de la base de test
    tmp_path.mkdir()
    (tmp_path / "notes.txt").write_text("bonjour")
    (tmp_path / "facture.pdf.exe").write_bytes(b"x")
    result = client.post("/api/scan/path", json={"path": str(tmp_path)}).json()
    assert result["type"] == "directory"
    assert result["files_examined"] == 2 and result["files_to_review"] == 1
    assert result["overall_level"] == "SUSPECT"

    single = client.post("/api/scan/path", json={
        "path": str(tmp_path / "notes.txt")}).json()
    assert single["type"] == "file"
    assert single["result"]["assessment"] == "AUCUN_INDICATEUR_DETECTE"

    assert client.post("/api/scan/path", json={
        "path": str(tmp_path / "absent")}).status_code == 404
    assert client.post("/api/scan/path", json={
        "path": str(tmp_path), "kind": "autre"}).status_code == 422
    # Aucun fichier analyse n'a ete modifie ou supprime.
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "facture.pdf.exe", "notes.txt"]


def test_monitor_cycle_and_listing_endpoints(client):
    summary = client.post("/api/monitor/run-once").json()
    assert summary["processes"] > 3
    processes = client.get("/api/processes").json()
    assert processes["count"] == summary["processes"]
    first = processes["processes"][0]
    assert "cmdline" not in first and "risk" in first
    assert client.get("/api/network").json()["available"] in (True, False)
    assert client.get("/api/file-activity").json()["baseline"] is True
    running = client.post("/api/scan/running-applications?limit=5").json()
    assert running["applications_examined"] >= 1
    assert all(a["executed"] is False for a in running["applications"])


def test_history_and_report(client):
    client.post("/api/scan/links", json={"urls": ["https://bit.ly/x"]})
    scans = client.get("/api/scans").json()["scans"]
    assert scans[0]["kind"] == "link" and "report" not in scans[0]
    full = client.get(f"/api/scans/{scans[0]['id']}").json()
    assert full["report"]["url"] == "https://bit.ly/x"
    assert client.get("/api/scans/9999").status_code == 404
    report = client.get("/api/report").json()
    assert report["counts"]["scans"] == 1 and "notice" in report


def test_monitor_thread_start_stop(client):
    started = client.post("/api/monitor/start", json={"interval": 2}).json()
    assert started["started"] is True and started["running"] is True
    assert client.post("/api/monitor/start", json={}).json()["started"] is False
    deadline = time.time() + 20
    while time.time() < deadline:
        if client.get("/api/status").json()["monitor"]["cycles"] >= 1:
            break
        time.sleep(0.5)
    status = client.post("/api/monitor/stop").json()
    assert status["running"] is False and status["cycles"] >= 1
    assert status["last_error"] is None
    assert client.post("/api/monitor/start", json={"interval": 1}).status_code == 422


def test_end_to_end_ransomware_like_activity_raises_high_alert(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    for i in range(30):
        (docs / f"doc{i}.txt").write_bytes(b"contenu normal " * 300)
    svc = MonitorService(Database(tmp_path / "e2e.db"), watch_dirs=[docs])
    try:
        svc.run_cycle()  # reference
        for i in range(30):
            (docs / f"doc{i}.txt").write_bytes(os.urandom(4096))
        svc.run_cycle()
        alerts = svc.alerts.list()
        activity = [a for a in alerts if a["source"] == "file_activity"]
        assert activity and activity[0]["level"] == "RISQUE_ELEVE"
        actions = activity[0]["details"]["decision"]["recommended_actions"]
        assert any("sauvegardes" in a for a in actions)
        # Rien n'a ete supprime : 30 fichiers toujours presents.
        assert len(list(docs.iterdir())) == 30
    finally:
        svc.db.close()
