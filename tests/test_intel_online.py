"""Renseignement local (listes) et API externes (interpretation, cache, garde-fous).

Aucun test ne touche le reseau : les services externes sont remplaces par un faux
transport qui renvoie des reponses de la FORME EXACTE documentee par chaque service.
"""
import gzip
import json

import pytest
from fastapi.testclient import TestClient

from cubernoyau.config import settings
from cubernoyau.intel import loaders
from cubernoyau.intel.online import interpret as I
from cubernoyau.intel.online.base import HttpClient, ProviderError
from cubernoyau.intel.online.manager import OnlineIntel
from cubernoyau.intel.store import IntelStore
from cubernoyau.intel.urls import normalize_url
from cubernoyau.storage.database import Database
from server.app import create_app
from server.service import MonitorService

SHA = "a" * 64


# ----------------------------------------------------------------- faux services
def fake_transport(calls=None, malicious=True):
    """Transport de test : repond comme les vrais services, et note les URL appelees."""
    def transport(method, url, headers, body, timeout):
        if calls is not None:
            calls.append((url, headers, body))
        if "mb-api.abuse.ch" in url:
            if malicious:
                return 200, json.dumps({"query_status": "ok", "data": [{
                    "signature": "Remcos", "file_type": "exe", "first_seen": "2026-05-01 10:00:00",
                    "tags": ["RAT"], "delivery_method": "email_attachment"}]}).encode()
            return 200, json.dumps({"query_status": "hash_not_found"}).encode()
        if "threatfox-api" in url:
            return 200, json.dumps({"query_status": "no_result", "data": "Your search did not yield any results"}).encode()
        if "urlhaus-api" in url and url.endswith("/url/"):
            return 200, json.dumps({"query_status": "ok", "url_status": "online", "threat": "malware_download",
                                    "date_added": "2026-10-13 08:28:20 UTC", "tags": ["Mozi"],
                                    "blacklists": {"spamhaus_dbl": "not listed", "surbl": "listed"},
                                    "payloads": [{}], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}).encode()
        if "urlhaus-api" in url:
            return 200, json.dumps({"query_status": "no_results"}).encode()
        if "phishtank" in url:
            return 200, json.dumps({"results": {"in_database": False}}).encode()
        if "virustotal" in url:
            return 404, b"{}"
        return 500, b""
    return transport


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "INTEL_DIR", tmp_path / "ti")
    monkeypatch.setattr(settings, "INTEL_HASH_MALWARE_DIR", tmp_path / "ti" / "hashes" / "malware")
    monkeypatch.setattr(settings, "INTEL_HASH_BENIGN_DIR", tmp_path / "ti" / "hashes" / "benign")
    monkeypatch.setattr(settings, "INTEL_URLS_DIR", tmp_path / "ti" / "urls")
    monkeypatch.setattr(settings, "EMBER_DIR", tmp_path / "ember")
    db = Database(tmp_path / "t.db")
    yield db, IntelStore(db), tmp_path
    db.close()


# ----------------------------------------------------------------- liens : normalisation
def test_normalize_url_ignores_scheme_case_fragment_and_trailing_slash():
    a = normalize_url("HTTP://Evil.Example.com:80/a/b/?x=1#top")[0]
    b = normalize_url("https://evil.example.com/a/b?x=1")[0]
    assert a == b == "evil.example.com/a/b?x=1"
    assert normalize_url("http://evil.example.com:8080/x")[0] == "evil.example.com:8080/x"
    assert normalize_url("")[0] == "" and normalize_url("http://")[0] == ""


# ----------------------------------------------------------------- listes locales
def test_parse_hash_lines_handles_csv_labels_and_noise():
    rows = list(loaders.parse_hash_lines([
        "# commentaire", SHA + ",wacatac", f'"2026-10-13 08:30:58","{"B" * 64}","exe"', "rien ici", "c" * 64], "src"))
    assert rows == [(SHA, "wacatac"), ("b" * 64, "exe"), ("c" * 64, None)]


def test_parse_url_lines_real_urlhaus_formats():
    lines = ["2026-10-13 08:28:20\thttp://219.156.19.56:35763/bin.sh\tOnline\t32-bit arm elf Mozi link\tgeenensp",
             "2026-10-13 07:07:17\thttps://github.com/MajorRaikage45/MimiLokinil/r...\tOnline\tdropper",   # tronque
             "https://aafesorder.com/31aa\tOffline\tc2\tAnonymous",
             "phish,https://facebooklogincc.blogspot.com/"]
    got = list(loaders.parse_url_lines(lines, "malware"))
    assert ("http://219.156.19.56:35763/bin.sh", "malware") in got
    assert not any("MimiLokinil" in u for u, _ in got)               # lien tronque ignore
    assert ("https://aafesorder.com/31aa", "c2") in got
    assert ("https://facebooklogincc.blogspot.com/", "phishing") in got


def test_store_lookup_exact_and_host(env):
    _db, store, _ = env
    store.add_urls([("http://evil.example/payload.exe", "malware", "urlhaus"),
                    ("evil-domain.example", "phishing", "feed")])
    hit = store.lookup_url("https://EVIL.example/payload.exe/")
    assert hit == {"match": "url", "kind": "malware", "source": "urlhaus"}
    assert store.lookup_url("http://evil-domain.example/login")["match"] == "host"
    assert store.lookup_url("http://safe.example/") is None


def test_sync_folders_is_incremental(env):
    _db, store, tmp = env
    (settings.INTEL_HASH_MALWARE_DIR).mkdir(parents=True)
    (settings.INTEL_URLS_DIR / "phishing").mkdir(parents=True)
    with gzip.open(settings.INTEL_HASH_MALWARE_DIR / "feed.csv.gz", "wt") as f:
        f.write(f"{SHA},Remcos\n{'d' * 64},AsyncRAT\n")
    (settings.INTEL_URLS_DIR / "phishing" / "pt.csv").write_text("1,http://bad.example/login,x\n")
    first = loaders.sync_intel_folders(store)
    assert {r["file"] for r in first} == {"hashes/malware/feed.csv.gz", "urls/phishing/pt.csv"}
    assert store.lookup_malware_hash(SHA) == "Remcos"
    assert store.lookup_url("http://bad.example/login")["kind"] == "phishing"
    assert loaders.sync_intel_folders(store) == []                     # rien de neuf : rien a faire
    assert len(loaders.sync_intel_folders(store, force=True)) == 2     # force : tout est relu


def test_bodmas_conversion(tmp_path):
    (tmp_path / "bodmas_metadata.csv").write_text(
        "sha,timestamp,family\n" + f"{'1' * 64},2020-01-01 00:00:00+00:00,\n"
        f"{'2' * 64},2020-01-02 00:00:00+00:00,wacatac\n")
    out = loaders.bodmas_to_intel_files(tmp_path, tmp_path / "out")
    assert out == {"malware": 1, "benign": 1}
    assert gzip.open(tmp_path / "out" / "malware" / "bodmas.csv.gz", "rt").read().count("wacatac") == 1


# ----------------------------------------------------------------- interpretation
def test_interpretation_rules_are_prudent():
    # MalwareBazaar : present = malveillant (critique) ; absent = inconnu, jamais "sain"
    v = I.malwarebazaar_hash({"query_status": "ok", "data": [{"signature": "Remcos", "file_type": "exe",
                                                               "first_seen": "2026-05-01 10:00:00"}]}, SHA)
    assert v["status"] == "malicious" and v["indicator"]["severity"] == "critical" and "Remcos" in v["headline"]
    assert I.malwarebazaar_hash({"query_status": "hash_not_found"}, SHA)["status"] == "unknown"
    # ThreatFox : la gravite suit la confiance
    ioc = lambda c: {"query_status": "ok", "data": [{"malware_printable": "X", "confidence_level": c, "threat_type": "botnet_cc"}]}  # noqa: E731
    assert [I.threatfox_hash(ioc(c), SHA)["indicator"]["severity"] for c in (100, 60, 20)] == ["critical", "high", "medium"]
    # URLhaus : en ligne = critique, hors ligne = eleve
    online = {"query_status": "ok", "url_status": "online", "threat": "malware_download", "date_added": "2026-10-13"}
    assert I.urlhaus_url(online, "u")["indicator"]["severity"] == "critical"
    assert I.urlhaus_url(dict(online, url_status="offline"), "u")["indicator"]["severity"] == "high"
    # PhishTank : seul "verifie ET actif" est critique
    pt = lambda **k: {"results": {"in_database": True, **k}}  # noqa: E731
    assert I.phishtank(pt(valid=True, verified=True), "u")["indicator"]["severity"] == "critical"
    assert I.phishtank(pt(valid=False, verified=True), "u")["indicator"]["severity"] == "medium"
    assert I.phishtank(pt(valid="false", verified="false"), "u")["indicator"]["severity"] == "low"
    assert I.phishtank({"results": {"in_database": False}}, "u")["status"] == "unknown"
    # VirusTotal : 5 moteurs = malveillant (seuil EMBER2024) ; 1-4 = prudence ; 0 = "propre" nuance
    vt = lambda m: {"data": {"attributes": {"last_analysis_stats": {"malicious": m, "undetected": 60, "harmless": 5}}}}  # noqa: E731
    assert [I.virustotal_file(vt(m), SHA)["status"] for m in (12, 5, 2, 0)] == ["malicious", "malicious", "suspicious", "clean"]
    assert I.virustotal_file(vt(12), SHA)["indicator"]["severity"] == "critical"
    assert I.virustotal_file(vt(1), SHA)["indicator"]["severity"] == "low"
    assert I.virustotal_file({"_http": 404}, SHA)["status"] == "unknown"


def test_summary_worst_status_wins_and_mentions_errors():
    vs = [I.malwarebazaar_hash({"query_status": "hash_not_found"}, SHA), I.error_verdict("virustotal", "panne"),
          I.urlhaus_url({"query_status": "ok", "url_status": "online", "threat": "malware_download"}, "u")]
    s = I.summarize(vs)
    assert s["status"] == "malicious" and "URLhaus" in s["text"] and "1/3" in s["text"]
    assert I.summarize([]) is None


# ----------------------------------------------------------------- gestionnaire
def test_online_is_off_by_default_and_sends_nothing(env):
    db, store, _ = env
    calls = []
    online = OnlineIntel(db, store, fake_transport(calls))
    assert online.check_hash(SHA)["enabled"] is False and online.check_url("http://x.example")["enabled"] is False
    assert calls == []


def test_online_check_cache_keys_and_errors(env):
    db, store, _ = env
    calls = []
    online = OnlineIntel(db, store, fake_transport(calls))
    shown = online.update_settings(master=True, keys={"abusech": "SECRETKEY1234"})
    assert "SECRETKEY1234" not in json.dumps(shown) and "1234" in json.dumps(shown)   # cle jamais renvoyee
    result = online.check_hash(SHA)
    assert result["summary"]["status"] == "malicious"
    assert {v["provider"] for v in result["verdicts"]} == {"malwarebazaar", "threatfox", "urlhaus"}  # pas de cle VT
    assert all(c[1].get("Auth-Key") == "SECRETKEY1234" for c in calls)
    n = len(calls)
    online.check_hash(SHA)
    assert len(calls) == n                                                          # reponse en cache
    # panne reseau : verdict "error", jamais d'exception ; non mis en cache
    def broken(*a):
        raise ProviderError("hors ligne")
    broken_online = OnlineIntel(db, store, broken)
    r = broken_online.check_hash("e" * 64)
    assert all(v["status"] == "error" for v in r["verdicts"]) and r["indicators"] == []
    # cle refusee (401) : message clair
    denied = OnlineIntel(db, store, lambda *a: (401, b"{}"))
    assert "Acces refuse" in denied.check_hash("f" * 64)["verdicts"][0]["headline"]


def test_online_test_button_and_per_provider_switch(env):
    db, store, _ = env
    online = OnlineIntel(db, store, fake_transport())
    assert online.test("malwarebazaar")["ok"] is False                              # pas de cle
    online.update_settings(master=True, keys={"abusech": "K"})
    assert online.test("malwarebazaar")["ok"] is True and online.test("nope")["ok"] is False
    online.update_settings(enabled={"threatfox": False})
    assert "threatfox" not in {v["provider"] for v in online.check_hash(SHA)["verdicts"]}


def test_http_client_error_mapping():
    c = lambda status, body=b"{}": HttpClient(lambda *a: (status, body))  # noqa: E731
    with pytest.raises(ProviderError, match="Acces refuse"):
        c(403).request("GET", "https://x")
    with pytest.raises(ProviderError, match="Quota"):
        c(429).request("GET", "https://x")
    with pytest.raises(ProviderError, match="illisible"):
        c(200, b"<html>").request("GET", "https://x")
    assert c(404).request("GET", "https://x") == {"_http": 404}


# ----------------------------------------------------------------- integration (analyses + API)
@pytest.fixture()
def client(env, monkeypatch):
    db, _store, tmp = env
    svc = MonitorService(db, watch_dirs=[], online_transport=fake_transport())
    with TestClient(create_app(svc, autostart=False)) as c:
        yield c, svc


def test_link_scan_uses_local_lists_and_online(client):
    c, svc = client
    svc.intel.add_urls([("http://evil.example/bin.sh", "malware", "urlhaus")])
    r = c.post("/api/scan/links", json={"urls": ["http://evil.example/bin.sh"]}).json()["results"][0]
    assert "KNOWN_MALICIOUS_URL" in {i["code"] for i in r["risk_indicators"]}
    assert r["risk"]["level"] == "RISQUE_ELEVE" and "online" not in r             # API externes eteintes
    c.post("/api/online/settings", json={"master": True, "keys": {"abusech": "K"}})
    r = c.post("/api/scan/links", json={"urls": ["http://other.example/x"]}).json()["results"][0]
    assert r["online"]["summary"]["status"] == "malicious"                          # URLhaus "online" (faux service)
    assert "ONLINE_URLHAUS_MALICIOUS" in {i["code"] for i in r["risk_indicators"]}


def test_file_scan_with_known_malware_online(client, tmp_path):
    c, _svc = client
    c.post("/api/online/settings", json={"master": True, "keys": {"abusech": "K"}})
    p = tmp_path / "inoffensif.txt"
    p.write_text("contenu quelconque")
    with open(p, "rb") as f:
        r = c.post("/api/scan/file", files={"file": ("inoffensif.txt", f)}).json()
    assert r["risk"]["level"] == "RISQUE_ELEVE"                                     # MalwareBazaar dit "connu"
    assert r["online"]["verdicts"][0]["headline"].startswith("fichier connu comme malveillant")
    assert "ONLINE_MALWAREBAZAAR_KNOWN" in {i["code"] for i in r["risk_indicators"]}


def test_known_benign_hash_is_informational_only(client, tmp_path):
    c, svc = client
    p = tmp_path / "notes.txt"
    p.write_text("document sain")
    with open(p, "rb") as f:
        sha = c.post("/api/scan/file", files={"file": ("notes.txt", f)}).json()["sha256"]
    svc.intel.add_benign_hashes([(sha, "bodmas")])
    with open(p, "rb") as f:
        r = c.post("/api/scan/file", files={"file": ("notes.txt", f)}).json()
    assert r["deep"]["known_benign"] == "bodmas" and r["risk"]["level"] == "AUCUN_INDICATEUR_DETECTE"


def test_api_online_settings_check_and_datasets(client):
    c, _svc = client
    s = c.get("/api/online/settings").json()
    assert s["master"] is False and {p["id"] for p in s["providers"]} >= {"malwarebazaar", "virustotal"}
    assert c.post("/api/online/check", json={"kind": "hash", "value": SHA}).status_code == 409   # desactive
    c.post("/api/online/settings", json={"master": True, "keys": {"abusech": "K"}})
    assert c.post("/api/online/check", json={"kind": "hash", "value": "zzz"}).status_code == 400
    ok = c.post("/api/online/check", json={"kind": "hash", "value": SHA}).json()
    assert ok["summary"]["status"] == "malicious"
    assert c.post("/api/online/test/malwarebazaar").json()["ok"] is True
    d = c.get("/api/datasets").json()
    assert {x["name"] for x in d["datasets"]} >= {"bodmas", "sorel20m", "thezoo", "custom_malware", "custom_benign"}
    r = c.post("/api/intel/urls", json={"text": "http://bad.example/a\nhttp://bad.example/b", "kind": "phishing"}).json()
    assert r["urls_added"] == 2 and r["counts"]["malicious_urls"] == 2
    assert c.post("/api/datasets/bodmas/nimporte_quoi").status_code == 404
