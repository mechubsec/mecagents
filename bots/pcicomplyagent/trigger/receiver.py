"""Commit-notification receiver: a commit on the target device starts a pcicomplyagent run.

POST /commit from ALLOWED_SOURCE with the shared secret header starts
pcicomplyagent-triggered.service. A notice that cannot start a run at once (the scheduled weekly collect is running,
a triggered run is running, or the last start was under a minute ago) is answered 202 and kept (the latest one): one
more run starts once both units are idle, so no commit goes unreviewed and the units never queue on the state lock. The body is never acted on: it is only
logged, and (device, user) are kept, length-capped and defanged, as a small note file the run
may show as "committed by ..." (untrusted: the device's own words).
"""
import json
import hmac
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BIND = os.environ.get("TRIGGER_BIND", "192.0.2.10")
PORT = int(os.environ.get("TRIGGER_PORT", "8802"))
ALLOWED_SOURCE = os.environ.get("TRIGGER_ALLOWED_SOURCE", "192.0.2.20")
SECRET_FILE = Path(os.environ.get("TRIGGER_SECRET_FILE", Path.home() / ".config/labbots/pcicomplyagent-trigger.secret"))
NOTE_FILE = Path(os.environ.get("TRIGGER_NOTE_FILE", Path.home() / ".local/state/labbots/pcicomplyagent-trigger.json"))
UNIT = "pcicomplyagent-triggered.service"
SCHEDULED_UNIT = "labbot@pcicomplyagent.collect.service"  # the weekly collect
POLL_SECONDS = 15
HEADER = "X-Trigger-Secret"
MAX_BODY = 512
DEBOUNCE_SECONDS = 60

_last_start = 0.0
_deferred: dict | None = None  # the note of a commit notice waiting for both units to be idle
_handoff = threading.Lock()  # a notice's start-or-defer decision and the waiter's check-and-start never interleave


def source_ok(client_ip: str, allowed: str = ALLOWED_SOURCE) -> bool:
    """True only for the device's management IP."""
    return client_ip == allowed


def secret_ok(presented: str | None, expected: str) -> bool:
    """Constant-time compare; an empty expected secret never matches."""
    if not presented or not expected:
        return False
    return hmac.compare_digest(presented.encode(), expected.encode())


def read_capped(stream, length_header: str | None, cap: int = MAX_BODY) -> bytes | None:
    """Read the body, or None if Content-Length is missing, bad or over the cap."""
    if not length_header or not length_header.isdigit() or int(length_header) > cap:
        return None
    return stream.read(int(length_header))


def defang(body: bytes, cap: int = 200) -> str:
    """Log-safe note: ASCII printable only, capped."""
    return re.sub(r"[^ -~]", "?", body.decode("ascii", "replace"))[:cap]


def parse_note(body: bytes, now: float) -> dict:
    """{device, user, at} from a body like `device=NAME user=NAME`; each value capped at 32 printable characters.
    Anything else in the body is ignored."""
    text = defang(body, 200)
    pick = lambda field: (re.search(rf"\b{field}=(\S{{1,32}})", text) or [None, ""])[1]
    return {"device": pick("device"), "user": pick("user"), "at": now}


def write_note(note: dict, path: Path = NOTE_FILE) -> None:
    """Leave the note for the triggered run: atomic, mode 600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(note, handle)
    os.replace(temp, path)


def should_start(now: float, last_start: float, running: bool, debounce: int = DEBOUNCE_SECONDS, scheduled: bool = False) -> str:
    """'running' (the triggered unit is active), 'deferred' (the scheduled collect is running), 'debounced' or 'start'."""
    if running:
        return "running"
    if scheduled:
        return "deferred"
    if now - last_start < debounce:
        return "debounced"
    return "start"


def unit_active(unit: str) -> bool:
    """Whether the user unit is active or starting."""
    state = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True).stdout.strip()
    return state in ("active", "activating")


def start_run(note: dict) -> None:
    """Leave the note (stamped now) for the run and start the triggered unit."""
    global _last_start
    _last_start = time.time()
    try:
        write_note({**note, "at": _last_start})
    except OSError as exc:  # a missing note only costs the "by <user>" detail
        log(f"could not write the note: {type(exc).__name__}")
    subprocess.run(["systemctl", "--user", "start", "--no-block", UNIT])


def wait_then_start() -> None:
    """Wait until neither the scheduled collect nor a triggered run is active and the debounce has passed, then start the
    one deferred run (with the latest note). The deferral is handed over before the start: a notice that arrives from
    then on belongs to a new waiter, and this one never touches it again. A failed wait clears the deferral."""
    global _deferred
    try:
        while True:
            with _handoff:  # checked and started in one step: a notice deciding at the same moment sees this run or goes first
                if not (unit_active(SCHEDULED_UNIT) or unit_active(UNIT) or time.time() - _last_start < DEBOUNCE_SECONDS):
                    log("units idle: starting the deferred run")
                    note, _deferred = _deferred, None
                    return start_run(note)
            time.sleep(POLL_SECONDS)
    except BaseException:
        _deferred = None
        raise


def defer(note: dict) -> None:
    """Keep the latest note; the first deferral starts the waiter, later ones only replace the note."""
    global _deferred
    first = _deferred is None
    _deferred = note
    if first:
        threading.Thread(target=wait_then_start, daemon=True).start()


def log(message: str) -> None:
    """Log one line to stdout (journald)."""
    print(message, flush=True)


class Handler(BaseHTTPRequestHandler):
    """POST /commit only."""

    def _reply(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args) -> None:  # silence default access log
        pass

    def do_POST(self) -> None:
        """Validate, start the run or keep the notice for one later run, answer 202."""
        client = self.client_address[0]
        if self.path != "/commit":
            return self._reply(404)
        if not source_ok(client):
            return self._reply(403)
        expected = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else ""
        if not secret_ok(self.headers.get(HEADER), expected):
            log(f"rejected bad secret from {client}")
            return self._reply(403)
        body = read_capped(self.rfile, self.headers.get("Content-Length"))
        if body is None:
            return self._reply(404)
        with _handoff:
            verdict = should_start(time.time(), _last_start, unit_active(UNIT), scheduled=unit_active(SCHEDULED_UNIT))
            log(f"commit notice from {client}: {defang(body)!r} -> {verdict}")
            if verdict == "start":
                start_run(parse_note(body, time.time()))
            else:  # running, deferred or debounced: one more run once the units are idle
                defer(parse_note(body, time.time()))
        self._reply(202)


def main() -> None:
    """Serve forever."""
    log(f"listening on {BIND}:{PORT}")
    HTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
