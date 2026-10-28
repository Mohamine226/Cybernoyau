import os
import random

from cubernoyau.analysis.application_analyzer import (
    analyze_application, detect_application_risks, shannon_entropy)
from cubernoyau.analysis.behavior_analyzer import ProcessBehaviorAnalyzer
from cubernoyau.analysis.file_activity_monitor import FileActivityMonitor
from cubernoyau.analysis.file_analyzer import analyze_file
from cubernoyau.analysis.link_analyzer import analyze_url
from cubernoyau.analysis.network_analyzer import analyze_connections
from cubernoyau.models.model_manager import ProcessAnomalyModel


def codes(result):
    return {i["code"] for i in result["risk_indicators"]}


# ---------- liens
def test_safe_link_has_no_indicator():
    assert analyze_url("https://docs.python.org/3/")["assessment"] == \
        "AUCUN_INDICATEUR_DETECTE"


def test_userinfo_trick_is_high_risk():
    r = analyze_url("http://paypal.com@secure-login.example.tk/verify")
    assert "USERINFO_IN_URL" in codes(r)
    assert r["assessment"] == "RISQUE_ELEVE"


def test_brand_impersonation_and_legit_brand():
    assert "BRAND_IMPERSONATION_PATTERN" in codes(
        analyze_url("https://paypal-login.verify-account.xyz"))
    assert "BRAND_IMPERSONATION_PATTERN" not in codes(
        analyze_url("https://www.paypal.com/signin"))


def test_punycode_ip_and_shortener():
    assert "PUNYCODE_DOMAIN" in codes(analyze_url("https://xn--pypal-4ve.com"))
    assert "IP_ADDRESS_HOST" in codes(analyze_url("http://192.168.1.5:8080/x"))
    assert "URL_SHORTENER" in codes(analyze_url("https://bit.ly/abc"))


def test_link_never_opened_and_handles_garbage():
    assert analyze_url("https://bit.ly/x")["opened"] is False
    analyze_url("http://[::1")  # URL mal formee : ne doit pas lever
    analyze_url("")


# ---------- fichiers / applications
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_double_extension_file(tmp_path):
    f = tmp_path / "facture.pdf.exe"
    f.write_bytes(b"not a program")
    result = analyze_file(f)
    assert "MISLEADING_DOUBLE_EXTENSION" in codes(result)
    assert result["executed"] is False
    assert len(result["sha256"]) == 64


def test_fake_exe_header_mismatch(tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"hello")
    assert "EXTENSION_HEADER_MISMATCH" in codes(analyze_application(f))


def test_real_pe_header_is_accepted(tmp_path):
    f = tmp_path / "ok.exe"
    data = bytearray(256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    f.write_bytes(bytes(data))
    result = analyze_application(f)
    assert result["pe_header_valid"] is True
    assert "EXTENSION_HEADER_MISMATCH" not in codes(result)


def test_pe_with_wrong_extension_is_high(tmp_path):
    f = tmp_path / "photo.jpg"
    data = bytearray(256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    f.write_bytes(bytes(data))
    assert "PE_WITH_NON_EXECUTABLE_EXTENSION" in codes(analyze_application(f))


def test_unsigned_in_user_location_rule():
    file_result = {"extension": ".exe",
                   "file_path": "C:\\Users\\x\\Downloads\\a.exe",
                   "digital_signature": {"status": "NotSigned"}}
    pe = {"is_pe": True, "entropy": 5.0, "sample_bytes": 100}
    found = {i["code"] for i in detect_application_risks(file_result, pe)}
    assert {"UNSIGNED_IN_USER_LOCATION", "USER_WRITABLE_LOCATION"} <= found


# ---------- comportement des processus
def proc(pid, name, parent=None, exe="", cmd="", cpu=0.0):
    return {"pid": pid, "name": name, "parent_name": parent,
            "executable": exe, "cmdline": cmd, "cpu_percent": cpu,
            "created_at": "2026-01-01T00:00:00+00:00"}


def test_office_spawning_shell_is_high():
    result = ProcessBehaviorAnalyzer().analyze(
        [proc(1, "cmd.exe", "WINWORD.EXE", r"C:\Windows\System32\cmd.exe")])
    assert result[1][0]["code"] == "OFFICE_SPAWNS_SCRIPT_HOST"
    assert result[1][0]["severity"] == "high"


def test_powershell_encoded_hidden():
    result = ProcessBehaviorAnalyzer().analyze([proc(
        2, "powershell.exe", "explorer.exe", "",
        "powershell.exe -NoP -w hidden -enc SQBFAFgA")])
    found = {i["code"] for i in result[2]}
    assert {"POWERSHELL_ENCODED_COMMAND", "POWERSHELL_HIDDEN_WINDOW"} <= found


def test_normal_processes_have_no_indicator():
    result = ProcessBehaviorAnalyzer().analyze([
        proc(3, "chrome.exe", "explorer.exe",
             r"C:\Program Files\Google\Chrome\chrome.exe"),
        proc(4, "powershell.exe", "explorer.exe", "", "powershell.exe -File a.ps1"),
    ])
    assert result[3] == [] and result[4] == []


def test_masquerading_system_name():
    result = ProcessBehaviorAnalyzer().analyze([proc(
        5, "svchost.exe", "explorer.exe",
        r"C:\Users\x\AppData\Local\svchost.exe")])
    assert "WINDOWS_LIKE_NAME_UNUSUAL_LOCATION" in {i["code"] for i in result[5]}


def test_sustained_cpu_needs_three_cycles_and_ignores_idle():
    analyzer = ProcessBehaviorAnalyzer()
    busy = [proc(6, "miner.exe", cpu=99), proc(7, "System Idle Process", cpu=99)]
    for _ in range(2):
        assert not analyzer.analyze(busy)[6]
    third = analyzer.analyze(busy)
    assert third[6][0]["code"] == "SUSTAINED_HIGH_CPU"
    assert 7 not in third
    analyzer.analyze([proc(6, "miner.exe", cpu=1)])
    assert not analyzer.analyze(busy)[6]  # serie remise a zero


# ---------- reseau
def conn(**kw):
    base = {"pid": 10, "process": "x.exe", "executable": r"C:\Prog\x.exe",
            "remote_ip": "8.8.8.8", "remote_port": 443,
            "status": "ESTABLISHED", "external": True}
    base.update(kw)
    return base


def test_network_rules():
    findings = analyze_connections([
        conn(pid=1, executable=r"C:\Users\u\AppData\Local\Temp\a.exe",
             remote_port=4444),
        conn(pid=2),
        conn(pid=3, status="LISTEN"),
        conn(pid=4, external=False),
    ])
    by_pid = {f["pid"]: {i["code"] for i in f["indicators"]} for f in findings}
    assert {"EXTERNAL_CONNECTION_FROM_TEMP_LOCATION",
            "UNCOMMON_REMOTE_PORT"} <= by_pid[1]
    assert by_pid[2] == set()
    assert 3 not in by_pid and 4 not in by_pid


def test_many_destinations_but_not_for_browsers():
    many = [conn(pid=5, process="bot.exe", remote_ip=f"8.8.{i // 250}.{i % 250}")
            for i in range(120)]
    browser = [conn(pid=6, process="chrome.exe", remote_ip=f"9.9.{i // 250}.{i % 250}")
               for i in range(120)]
    findings = {f["pid"]: f for f in analyze_connections(many + browser)}
    assert "MANY_EXTERNAL_DESTINATIONS" in {
        i["code"] for i in findings[5]["indicators"]}
    assert "MANY_EXTERNAL_DESTINATIONS" not in {
        i["code"] for i in findings[6]["indicators"]}


# ---------- activite de fichiers (type rancongiciel)
def make_files(directory, count, size=4096, ext=".txt", text=True):
    directory.mkdir(exist_ok=True)
    for i in range(count):
        data = (b"bonjour cubernoyau " * 300)[:size] if text else os.urandom(size)
        (directory / f"f{i}{ext}").write_bytes(data)


def test_baseline_then_quiet_cycle(tmp_path):
    make_files(tmp_path / "docs", 30)
    monitor = FileActivityMonitor([tmp_path / "docs"])
    assert monitor.scan()["baseline"] is True
    quiet = monitor.scan()
    assert quiet["indicators"] == [] and quiet["modified"] == 0


def test_mass_encryption_is_high(tmp_path):
    docs = tmp_path / "docs"
    make_files(docs, 30)
    monitor = FileActivityMonitor([docs])
    monitor.scan()
    make_files(docs, 30, text=False)  # contenu remplace par de l'aleatoire
    result = monitor.scan()
    assert {i["code"] for i in result["indicators"]} == {"MASS_HIGH_ENTROPY_WRITES"}
    assert result["indicators"][0]["severity"] == "high"


def test_mass_rename_with_new_extension_is_high(tmp_path):
    docs = tmp_path / "docs"
    make_files(docs, 25)
    monitor = FileActivityMonitor([docs])
    monitor.scan()
    for path in docs.iterdir():
        path.rename(path.with_suffix(".locked"))
    found = {i["code"]: i["severity"] for i in monitor.scan()["indicators"]}
    assert found.get("MASS_RENAME_NEW_EXTENSION") == "high"


def test_few_changes_and_compressed_downloads_are_not_flagged(tmp_path):
    docs = tmp_path / "docs"
    make_files(docs, 10)
    monitor = FileActivityMonitor([docs])
    monitor.scan()
    make_files(docs, 5, text=False)  # 5 fichiers seulement
    assert monitor.scan()["indicators"] == []
    make_files(docs, 30, ext=".zip", text=False)  # telechargement d'archives
    result = monitor.scan()
    assert "MASS_HIGH_ENTROPY_WRITES" not in {
        i["code"] for i in result["indicators"]}


def test_mass_deletion(tmp_path):
    docs = tmp_path / "docs"
    make_files(docs, 30)
    monitor = FileActivityMonitor([docs])
    monitor.scan()
    for path in list(docs.iterdir())[:25]:
        path.unlink()
    assert "MASS_FILE_DELETION" in {i["code"] for i in monitor.scan()["indicators"]}


# ---------- modele d'anomalies
def normal_row(rng):
    return {"has_executable_path": 1, "executable_path_length": rng.randint(30, 60),
            "name_length": rng.randint(6, 14), "process_age_log": rng.uniform(8, 11),
            "has_parent_process": 1, "is_system_account": rng.choice([0, 1]),
            "cpu_log": rng.uniform(0, 0.5), "memory_log": rng.uniform(16, 18),
            "threads_log": rng.uniform(1, 3)}


def test_isolation_forest_flags_outlier_only():
    rng = random.Random(1)
    rows = [normal_row(rng) for _ in range(80)]
    weird = {"has_executable_path": 0, "executable_path_length": 0,
             "name_length": 40, "process_age_log": 0.1, "has_parent_process": 0,
             "is_system_account": 0, "cpu_log": 4.5, "memory_log": 24,
             "threads_log": 7}
    results = ProcessAnomalyModel().score(rows + [weird])
    assert results[-1]["anomaly"] is True
    assert sum(r["anomaly"] for r in results[:-1]) <= 4  # ~contamination


def test_model_too_small_and_baseline_not_polluted():
    model = ProcessAnomalyModel()
    assert model.score([{}] * 3) == [None, None, None]
    rng = random.Random(2)
    rows = [normal_row(rng) for _ in range(50)]
    flagged = sum(r["anomaly"] for r in model.score(rows))
    assert len(model._baseline) == 50 - flagged
