"""Tests Android / mobile : analyse APK, jeton d'acces, fichiers PWA."""
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from cubernoyau.analysis.apk_analyzer import analyze_apk, extract_permissions, is_apk
from server.app import create_app
from server.service import MonitorService
from cubernoyau.storage.database import Database


def make_apk(path, permissions, utf16=False, manifest=True):
    blob = b""
    for perm in permissions:
        text = f"android.permission.{perm}"
        blob += (text.encode("utf-16le") if utf16 else text.encode()) + b"\x00\x01"
    with zipfile.ZipFile(path, "w") as z:
        if manifest:
            z.writestr("AndroidManifest.xml", blob)
        z.writestr("classes.dex", b"dex\n035\x00")
    return path


def codes(indicators):
    return {i["code"] for i in indicators}


def test_extract_permissions_ascii_and_utf16():
    assert extract_permissions(b"..android.permission.READ_SMS..") == ["READ_SMS"]
    raw = "android.permission.CAMERA".encode("utf-16le")
    assert extract_permissions(raw) == ["CAMERA"]


def test_banking_trojan_like_apk(tmp_path):
    apk = make_apk(tmp_path / "update.apk", [
        "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_SMS",
        "RECEIVE_SMS", "REQUEST_INSTALL_PACKAGES"], utf16=True)
    assert is_apk(apk)
    found = codes(analyze_apk(apk))
    assert {"APK_ACCESSIBILITY_SERVICE", "APK_OVERLAY", "APK_SMS_ACCESS",
            "APK_INSTALLS_PACKAGES"} <= found


def test_simple_apk_has_no_warning(tmp_path):
    apk = make_apk(tmp_path / "torch.apk", ["CAMERA"])
    found = codes(analyze_apk(apk))
    assert found == {"APK_PACKAGE"}


def test_apk_without_manifest_and_non_apk(tmp_path):
    apk = make_apk(tmp_path / "fake.apk", [], manifest=False)
    assert "APK_NO_MANIFEST" in codes(analyze_apk(apk))
    text = tmp_path / "notes.txt"
    text.write_text("bonjour")
    assert analyze_apk(text) == []
    broken = tmp_path / "broken.apk"
    broken.write_text("pas un zip")
    assert "APK_INVALID_ARCHIVE" in codes(analyze_apk(broken))


@pytest.fixture()
def service(tmp_path):
    svc = MonitorService(Database(tmp_path / "t.db"), watch_dirs=[])
    yield svc
    svc.stop()
    svc.db.close()


def test_apk_upload_through_api(service, tmp_path):
    apk = make_apk(tmp_path / "update.apk", [
        "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_SMS", "SEND_SMS"])
    with TestClient(create_app(service, autostart=False)) as client:
        with open(apk, "rb") as f:
            r = client.post("/api/scan/file", files={"file": ("update.apk", f)})
    assert r.status_code == 200
    data = r.json()
    assert "APK_ACCESSIBILITY_SERVICE" in codes(data["risk_indicators"])
    assert data["risk"]["level"] in ("SUSPECT", "RISQUE_ELEVE")


def test_token_required_when_configured(service):
    with TestClient(create_app(service, autostart=False, access_token="s3cret")) as c:
        assert c.get("/api/status").status_code == 401
        assert c.get("/api/status", headers={"X-Access-Token": "nope"}).status_code == 401
        assert c.get("/api/status", headers={"X-Access-Token": "s3cret"}).status_code == 200
        assert c.post("/api/monitor/stop").status_code == 401
        assert c.get("/").status_code == 200          # la page elle-meme reste chargeable


def test_pwa_files_served(service):
    with TestClient(create_app(service, autostart=False)) as c:
        manifest = c.get("/manifest.webmanifest")
        assert manifest.status_code == 200 and manifest.json()["name"] == "Mougle Protect"
        sw = c.get("/sw.js")
        assert sw.status_code == 200 and "javascript" in sw.headers["content-type"]
        assert sw.headers["service-worker-allowed"] == "/"
        assert c.get("/static/icon-192.png").content[:4] == b"\x89PNG"
        assert c.get("/static/icon-512.png").status_code == 200
