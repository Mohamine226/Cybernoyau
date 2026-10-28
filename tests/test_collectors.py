import json

from cubernoyau.collectors import process_collector
from cubernoyau.collectors.network_collector import collect_connections, is_external
from cubernoyau.features.extractor import extract_features


def test_collect_processes_has_core_fields():
    processes = process_collector.collect_processes()
    assert len(processes) > 3
    assert {"pid", "name", "cpu_percent", "num_threads"} <= processes[0].keys()


def test_cmdline_only_in_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(process_collector, "OUTPUT_DIR", tmp_path)
    processes = process_collector.collect_processes(include_cmdline=True)
    assert any(p.get("cmdline") for p in processes)
    saved = process_collector.save_processes(processes)
    assert "cmdline" not in json.loads(saved.read_text(encoding="utf-8"))[0]


def test_is_external():
    assert is_external("8.8.8.8")
    for ip in ("192.168.1.2", "10.0.0.1", "127.0.0.1", "169.254.1.1", "::1",
               "pas-une-ip"):
        assert not is_external(ip)


def test_collect_connections_structure():
    result = collect_connections()
    assert {"available", "error", "connections"} <= result.keys()
    for conn in result["connections"]:
        assert {"pid", "remote_ip", "remote_port", "external"} <= conn.keys()


def test_extract_features_is_numeric_and_safe():
    features = extract_features({"pid": 1, "name": "A.EXE", "cpu_percent": None,
                                 "memory_rss_bytes": "bad", "num_threads": 4})
    assert features["cpu_log"] == 0.0 and features["threads_log"] > 0
    assert features["name"] == "a.exe"
