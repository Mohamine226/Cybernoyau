from cubernoyau.alerts.alert_manager import AlertManager
from cubernoyau.alerts.recommendations import recommend
from cubernoyau.detection.decision_engine import decide
from cubernoyau.detection.risk_scorer import (
    LEVEL_HIGH, LEVEL_NONE, LEVEL_SUSPECT, score_indicators)
from cubernoyau.storage.database import Database


def ind(code, severity):
    return {"code": code, "severity": severity, "reason": code}


def test_no_indicator_is_none():
    assert score_indicators([])["level"] == LEVEL_NONE


def test_info_only_stays_none():
    assert score_indicators([ind("a", "info")])["level"] == LEVEL_NONE


def test_single_low_is_below_threshold():
    assert score_indicators([ind("a", "low")])["level"] == LEVEL_NONE


def test_two_lows_are_suspect():
    assert score_indicators(
        [ind("a", "low"), ind("b", "low")])["level"] == LEVEL_SUSPECT


def test_medium_is_suspect_high_is_high():
    assert score_indicators([ind("a", "medium")])["level"] == LEVEL_SUSPECT
    assert score_indicators([ind("a", "high")])["level"] == LEVEL_HIGH


def test_same_code_does_not_stack():
    once = score_indicators([ind("a", "medium")])["score"]
    many = score_indicators([ind("a", "medium")] * 10)["score"]
    assert once == many


def test_score_is_bounded_and_monotonic():
    base = score_indicators([ind("a", "medium")])["score"]
    more = score_indicators([ind("a", "medium"), ind("b", "medium")])["score"]
    assert base < more <= 100


def test_decision_never_acts_automatically():
    for level_ind in ("info", "medium", "high"):
        risk = score_indicators([ind("x", level_ind)])
        decision = decide("file", risk)
        assert decision["automatic_action"] == "aucune"
        assert decision["report_saved"] is True
        assert decision["alert"] == (risk["level"] != LEVEL_NONE)


def test_recommendations_exist_for_every_source_and_level():
    for source in ("file", "application", "link", "process", "network",
                   "file_activity", "inconnu"):
        for level in (LEVEL_SUSPECT, LEVEL_HIGH):
            assert len(recommend(source, level)) >= 2
    assert "ne garantit pas" in recommend("file", LEVEL_NONE)[0]


def test_alert_manager_cooldown_and_none_level():
    db = Database(":memory:")
    manager = AlertManager(db, cooldown=60)
    high = score_indicators([ind("a", "high")])
    none = score_indicators([])
    assert manager.raise_alert("file", "t", none, {}) is None
    assert manager.raise_alert("file", "t", high, {}) is not None
    assert manager.raise_alert("file", "t", high, {}) is None  # doublon
    assert manager.raise_alert("file", "autre", high, {}) is not None
    assert db.counts()["open_high"] == 2


def test_database_ack_and_filters():
    db = Database(":memory:")
    alert_id = db.add_alert("file", "t", LEVEL_HIGH, 60.0, {"k": "v"})
    assert db.list_alerts(acknowledged=False)[0]["details"] == {"k": "v"}
    assert db.acknowledge_alert(alert_id) is True
    assert db.acknowledge_alert(999) is False
    assert db.list_alerts(acknowledged=False) == []
    assert db.counts()["open_alerts"] == 0
