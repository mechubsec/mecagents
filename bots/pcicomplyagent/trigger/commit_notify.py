"""Junos event script (template): on UI_COMMIT_COMPLETED, POST one small notice to the trigger receiver.
Never fails a commit: every error is swallowed, and the POST has a 3 second timeout.

Before use, replace @@SECRET@@ with the receiver's shared secret when you transfer the file to the device (keep the
secret out of the repository), and point URL at your receiver. Set DEVICE to the device's name."""
import urllib.request

URL = "http://192.0.2.10:8802/commit"  # documentation-range placeholder: your receiver's address and port
SECRET = "@@SECRET@@"  # substituted at transfer time
DEVICE = "lab-vsrx"

try:
    try:
        from junos import Junos_Context
        who = Junos_Context.get("user-name", "?")
    except Exception:
        who = "?"
    req = urllib.request.Request(URL, data=("device=%s user=%s" % (DEVICE, who)).encode(),
                                 headers={"X-Trigger-Secret": SECRET}, method="POST")
    urllib.request.urlopen(req, timeout=3).read()
except Exception:
    pass
