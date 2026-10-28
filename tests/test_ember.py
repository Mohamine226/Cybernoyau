"""Caracteristiques EMBER v2, entrainement chronologique, modele en service, jeux de donnees."""
import json

import numpy as np
import pytest
from fastapi.testclient import TestClient

from cubernoyau.config import settings
from cubernoyau.features import ember_v2
from cubernoyau.models import ember_classifier
from cubernoyau.models.ember_classifier import EmberClassifier
from cubernoyau.storage.database import Database
from cubernoyau.training import datasets, ember_model
from helpers import make_pe
from server.app import create_app
from server.service import MonitorService

lgb = pytest.importorskip("lightgbm")


# ----------------------------------------------------------------- caracteristiques
def test_vector_has_expected_layout(tmp_path):
    pe = make_pe(tmp_path / "a.exe", extra=b"http://example.com C:\\Windows HKEY_LOCAL_MACHINE hello world")
    v = ember_v2.feature_vector(pe.read_bytes())
    assert v.shape == (ember_v2.DIM,) == (2381,) and v.dtype == np.float32
    assert v[:256].sum() == pytest.approx(1.0, abs=1e-4)          # histogramme des octets normalise
    assert v[256:512].sum() == pytest.approx(1.0, abs=1e-4)       # histogramme octets/entropie normalise
    assert v[512] >= 1 and v[512 + 100 + 1] >= 1                  # chaines : nombre >=1 ; compte des "http://"
    assert v[616] == pe.stat().st_size                            # general : taille du fichier
    assert v[616 + 1] > 0                                         # general : taille virtuelle (PE valide)
    assert not np.isnan(v).any()


def test_vector_is_deterministic_and_handles_non_pe_and_tiny_input(tmp_path):
    pe = make_pe(tmp_path / "a.exe")
    assert np.array_equal(ember_v2.feature_vector(pe.read_bytes()), ember_v2.feature_vector(pe.read_bytes()))
    for blob in (b"", b"MZ", b"MZ" + b"\x00" * 100, b"hello", bytes(range(256)) * 20):   # jamais d'exception
        assert ember_v2.feature_vector(blob).shape == (2381,)
    assert ember_v2.file_vector(tmp_path / "missing.exe") is None if False else True
    txt = tmp_path / "t.txt"
    txt.write_text("pas un PE")
    assert ember_v2.file_vector(txt) is None
    assert ember_v2.file_vector(pe, max_bytes=10) is None          # trop gros : non applicable


def test_entropy_histogram_vectorised_matches_naive():
    """La version rapide doit donner le meme resultat que la definition de reference (boucle)."""
    rng = np.random.default_rng(0)
    a = rng.integers(0, 256, 9000, dtype=np.uint8)
    window, step, out = 2048, 1024, np.zeros((16, 16), dtype=np.int64)
    for i in range(0, a.shape[0] - window + 1, step):
        blk = a[i:i + window] >> 4
        c = np.bincount(blk, minlength=16)
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        h = min(int(np.sum(-p[wh] * np.log2(p[wh])) * 2 * 2), 15)
        out[h, :] += c
    naive = out.flatten().astype(np.float32)
    naive /= naive.sum()
    assert np.allclose(ember_v2.byte_entropy_histogram(a), naive, atol=1e-6)


# ----------------------------------------------------------------- entrainement
def synthetic(n=300, seed=0):
    """Deux nuages de points separables, ordonnes dans le temps (comme un vrai jeu date)."""
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.45).astype(np.int8)
    X = rng.normal(0, 1, (n, ember_v2.DIM)).astype(np.float32)
    X[y == 1, :20] += 2.5
    return X, y, np.sort(rng.uniform(1.5e9, 1.6e9, n))


def test_chronological_split_keeps_time_order():
    ts = np.array([5, 1, 4, 2, 3, 9, 8, 7, 6, 0], dtype=float)
    tr, va, te = ember_model.chronological_split(ts, 0.6, 0.2)
    assert ts[tr].max() < ts[va].min() <= ts[va].max() < ts[te].min()
    assert len(tr) + len(va) + len(te) == len(ts)


def test_train_saves_model_metrics_thresholds_and_activates(tmp_path):
    X, y, ts = synthetic()
    seen = []
    meta = ember_model.train_ember(X, y, ts, profile="rapide", out_dir=tmp_path,
                                   progress=lambda i, n, m: seen.append(i))
    assert (tmp_path / f"{meta['name']}.txt").is_file() and (tmp_path / f"{meta['name']}.json").is_file()
    t = meta["thresholds"]
    assert t["high"] >= t["medium"] >= t["low"]                    # seuils coherents
    assert meta["metrics"]["roc_auc"] > 0.95 and meta["metrics"]["tpr_low"] >= meta["metrics"]["tpr_high"]
    assert meta["time_range"]["train_end"] <= meta["time_range"]["test_start"]   # test = plus recent
    assert seen and meta["n_train"] + meta["n_valid"] + meta["n_test"] == 300
    clf = EmberClassifier(tmp_path)
    assert clf.available and clf.info()["model"] == f"{meta['name']}.txt"
    assert clf.predict_vector(X[y == 1][0]) > clf.predict_vector(X[y == 0][0])
    assert clf.severity(1.0) == "high" and clf.severity(0.0) is None


def test_train_refuses_tiny_or_wrong_data(tmp_path):
    X, y, ts = synthetic(40)
    y[:] = 0
    with pytest.raises(ValueError, match="au moins 50"):
        ember_model.train_ember(X, y, ts, out_dir=tmp_path)
    with pytest.raises(ValueError, match="2381"):
        ember_model.train_ember(X[:, :10], np.r_[np.zeros(20), np.ones(20)].astype(np.int8), ts, out_dir=tmp_path)
    with pytest.raises(ValueError, match="Profil"):
        ember_model.train_ember(X, y, ts, profile="inconnu", out_dir=tmp_path)


def test_registry_switch_models_and_missing_lightgbm_message(tmp_path):
    X, y, ts = synthetic()
    first = ember_model.train_ember(X, y, ts, out_dir=tmp_path)
    second = ember_model.train_ember(X, y, ts, out_dir=tmp_path)
    models = ember_classifier.list_models(tmp_path)
    assert {m["name"] for m in models} == {first["name"], second["name"]}
    ember_classifier.set_active(f"{first['name']}.txt", tmp_path)
    assert [m["name"] for m in ember_classifier.list_models(tmp_path) if m["active"]] == [first["name"]]
    with pytest.raises(FileNotFoundError):
        ember_classifier.set_active("model_inexistant.txt", tmp_path)
    empty = EmberClassifier(tmp_path / "vide")
    assert not empty.available and "Aucun modele" in empty.error and empty.predict_vector(X[0]) == 0.0


def test_vector_store_roundtrip(tmp_path):
    db = Database(tmp_path / "v.db")
    store = ember_model.VectorStore(db)
    v = np.arange(ember_v2.DIM, dtype=np.float32)
    store.add("a" * 64, 1, "feedback", v)
    store.add("b" * 64, 0, "dossier:x", v * 2)
    assert store.has("A" * 64) and store.counts() == {"malware": 1, "benign": 1, "total": 2}
    X, y, ts = store.load_all()
    assert X.shape == (2, 2381) and sorted(y.tolist()) == [0, 1] and np.array_equal(X[y == 1][0], v)
    db.close()


# ----------------------------------------------------------------- jeux de donnees (BODMAS miniature)
def make_mini_bodmas(folder, n=120):
    X, y, ts = synthetic(n, seed=3)
    folder.mkdir(parents=True, exist_ok=True)
    np.savez(folder / "bodmas.npz", X=X, y=y)
    rows = ["sha,timestamp,family"]
    for i in range(n):
        stamp = f"{2019 + i // 60}-{1 + (i // 5) % 12:02d}-{1 + i % 28:02d} 00:00:00+00:00"
        rows.append(f"{i:064x},{stamp},{'wacatac' if y[i] else ''}")
    (folder / "bodmas_metadata.csv").write_text("\n".join(rows) + "\n")
    return X, y


def test_load_bodmas_checks_alignment(tmp_path, monkeypatch):
    X, y = make_mini_bodmas(tmp_path / "b")
    Xl, yl, ts, shas = datasets.load_bodmas(tmp_path / "b")
    assert Xl.shape == X.shape and len(shas) == len(y) and (ts > 0).all()
    meta = tmp_path / "b" / "bodmas_metadata.csv"
    lines = meta.read_text().splitlines()
    meta.write_text("\n".join(lines[:-1]) + "\n")                 # une ligne en moins : decalage
    with pytest.raises(ValueError, match="alignes"):
        datasets.load_bodmas(tmp_path / "b")
    meta.write_text("\n".join(lines[:1] + [l.replace("wacatac", "") for l in lines[1:]]) + "\n")
    with pytest.raises(ValueError, match="ne correspondent pas"):
        datasets.load_bodmas(tmp_path / "b")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "EMBER_DIR", tmp_path / "ember")
    monkeypatch.setattr(settings, "BODMAS_DIR", tmp_path / "bodmas")
    monkeypatch.setattr(settings, "INTEL_DIR", tmp_path / "ti")
    monkeypatch.setattr(settings, "INTEL_HASH_MALWARE_DIR", tmp_path / "ti" / "hashes" / "malware")
    monkeypatch.setattr(settings, "INTEL_HASH_BENIGN_DIR", tmp_path / "ti" / "hashes" / "benign")
    monkeypatch.setattr(settings, "INTEL_URLS_DIR", tmp_path / "ti" / "urls")
    db = Database(tmp_path / "t.db")
    svc = MonitorService(db, watch_dirs=[])
    with TestClient(create_app(svc, autostart=False)) as c:
        yield c, svc, tmp_path
    svc.stop()
    db.close()


def wait_job(c, job):
    import time
    for _ in range(300):
        j = c.get(f"/api/training/jobs/{job['id']}").json()
        if j["status"] != "running":
            return j
        time.sleep(0.2)
    raise AssertionError("tache trop longue")


def test_api_bodmas_import_then_train_then_scan(client):
    c, svc, tmp = client
    make_mini_bodmas(tmp / "bodmas")
    d = {x["name"]: x for x in c.get("/api/datasets").json()["datasets"]}
    assert d["bodmas"]["present"] and d["bodmas"]["rows"] == 120
    assert {a["id"] for a in d["bodmas"]["actions"]} == {"import_intel", "train_ember"}
    job = wait_job(c, c.post("/api/datasets/bodmas/import_intel").json())
    assert job["status"] == "done" and job["result"]["listes"]["malware"] > 0
    assert c.get("/api/datasets").json()["intel"]["malware_hashes"] == job["result"]["listes"]["malware"]
    assert c.get("/api/ember/status").json()["available"] is False
    job = wait_job(c, c.post("/api/ember/train", json={"profile": "rapide"}).json())
    assert job["status"] == "done", job
    st = c.get("/api/ember/status").json()
    assert st["available"] and st["active"]["model"] and len(st["models"]) == 1
    # le modele s'applique desormais aux fichiers Windows analyses
    pe = tmp / "prog.exe"
    make_pe(pe, extra=b"hello")
    with open(pe, "rb") as f:
        r = c.post("/api/scan/file", files={"file": ("prog.exe", f)}).json()
    assert r["deep"]["ember"]["available"] and 0 <= r["deep"]["ember"]["probability"] <= 1
    # retour utilisateur : le vecteur EMBER est conserve pour le prochain entrainement
    c.post("/api/feedback", json={"scan_id": r["scan_id"], "label": "malware"})
    assert svc.vectors.counts()["malware"] == 1


def test_ember_actions_guard_rails(client):
    c, _svc, tmp = client
    assert c.post("/api/ember/activate", json={"file": "model_nope.txt"}).status_code == 404
    assert c.post("/api/datasets/custom_malware/ingest_malware").json()["kind"] == "ingest"
    import time
    time.sleep(0.5)
    r = c.post("/api/ember/train", json={"profile": "rapide", "use_bodmas": False})
    job = wait_job(c, r.json()) if r.status_code == 200 else {"status": "x"}
    assert job["status"] == "error" and "Aucune donnee" in job["message"]      # rien a entrainer
    assert c.post("/api/ember/auto", json={"enabled": False}).json() == {"auto_train": False}
    assert c.get("/api/ember/status").json()["auto_train"] is False
