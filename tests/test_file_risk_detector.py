"""Regles de nom/emplacement des fichiers (ancien script de demonstration, converti en test)."""
from cubernoyau.analysis.file_risk_detector import detect_file_risks


def example(name, ext, path, status):
    return {"file_name": name, "extension": ext, "file_path": path,
            "digital_signature": {"status": status}}


def codes(result):
    return {i["code"] for i in result["indicators"]}


def test_plain_document_has_no_indicator():
    r = detect_file_risks(example("notes.txt", ".txt", r"C:\Users\Test\Documents\notes.txt", "not_checked"))
    assert r["risk_indicators_count"] == 0


def test_double_extension_is_flagged():
    r = detect_file_risks(example("facture.pdf.exe", ".exe", r"C:\Users\Test\Downloads\facture.pdf.exe", "NotSigned"))
    assert "MISLEADING_DOUBLE_EXTENSION" in codes(r)


def test_system_name_in_user_folder_is_flagged():
    r = detect_file_risks(example("svchost.exe", ".exe", r"C:\Users\Test\AppData\Local\svchost.exe", "NotSigned"))
    assert "WINDOWS_LIKE_NAME_UNUSUAL_LOCATION" in codes(r)
