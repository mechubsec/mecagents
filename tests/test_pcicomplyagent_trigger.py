"""Pure-function tests for the pcicomplyagent commit-trigger receiver (no network)."""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bots" / "pcicomplyagent" / "trigger"))
import receiver  # noqa: E402


def test_source_check():
    assert receiver.source_ok("192.0.2.20", "192.0.2.20")
    assert not receiver.source_ok("192.0.2.99", "192.0.2.20")


def test_secret_check():
    assert receiver.secret_ok("abc", "abc")
    assert not receiver.secret_ok("abd", "abc")
    assert not receiver.secret_ok(None, "abc")
    assert not receiver.secret_ok("", "")


def test_body_cap():
    assert receiver.read_capped(io.BytesIO(b"hello"), "5") == b"hello"
    assert receiver.read_capped(io.BytesIO(b"x" * 600), "600") is None
    assert receiver.read_capped(io.BytesIO(b""), None) is None
    assert receiver.read_capped(io.BytesIO(b""), "-1") is None


def test_defang():
    assert receiver.defang(b"a\x00b\nc\xff") == "a?b?c?"
    assert len(receiver.defang(b"x" * 1000)) == 200


def test_debounce_and_running():
    assert receiver.should_start(1000, 0, False) == "start"
    assert receiver.should_start(1030, 1000, False) == "debounced"
    assert receiver.should_start(1061, 1000, False) == "start"
    assert receiver.should_start(5000, 0, True) == "running"


def test_note_keeps_only_capped_device_and_user(tmp_path):
    note = receiver.parse_note(b"device=lab-vsrx user=ne\x00tconf extra=ignored", 1234.0)
    assert note == {"device": "lab-vsrx", "user": "ne?tconf", "at": 1234.0}
    assert receiver.parse_note(b"garbage", 1.0) == {"device": "", "user": "", "at": 1.0}
    assert len(receiver.parse_note(b"user=" + b"x" * 400, 1.0)["user"]) == 32
    path = tmp_path / "sub" / "note.json"
    receiver.write_note(note, path)
    assert path.stat().st_mode & 0o777 == 0o600 and sorted(p.name for p in path.parent.iterdir()) == ["note.json"]


def test_a_running_scheduled_collect_defers_the_start():
    assert receiver.should_start(5000, 0, False, scheduled=True) == "deferred"
    assert receiver.should_start(5000, 0, True, scheduled=True) == "running"  # the triggered unit itself is already active
    assert receiver.should_start(5000, 0, False, scheduled=False) == "start"


def test_deferral_keeps_the_latest_note_and_starts_one_run_after_the_scheduled_collect(monkeypatch):
    started, threads = [], []
    monkeypatch.setattr(receiver, "_deferred", None)
    monkeypatch.setattr(receiver.threading, "Thread", lambda target, daemon: type("T", (), {"start": lambda self: threads.append(target)})())
    receiver.defer({"user": "first"})
    receiver.defer({"user": "second"})
    assert len(threads) == 1 and receiver._deferred == {"user": "second"}  # a second notice replaces the note, no second waiter
    states = iter([True, True, False])
    monkeypatch.setattr(receiver, "unit_active", lambda unit: unit == receiver.SCHEDULED_UNIT and next(states))
    monkeypatch.setattr(receiver.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(receiver, "start_run", lambda note: started.append(note))
    threads[0]()
    assert started == [{"user": "second"}] and receiver._deferred is None


def test_start_run_stamps_the_note_now_and_starts_the_unit(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(receiver, "NOTE_FILE", tmp_path / "n.json")
    monkeypatch.setattr(receiver, "write_note", lambda note, path=None: commands.append(("note", note)))
    monkeypatch.setattr(receiver.subprocess, "run", lambda command, **kwargs: commands.append(command))
    receiver.start_run({"device": "d", "user": "u", "at": 1.0})
    assert commands[0][0] == "note" and commands[0][1]["at"] > 1.0 and commands[1] == ["systemctl", "--user", "start", "--no-block", receiver.UNIT]
