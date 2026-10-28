import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

FIX = pathlib.Path(__file__).resolve().parents[2] / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


SCHEMAS = load("schemas.json")
MALFORMED = load("malformed.json")
VALID = load("valid.json")
BY_ID = {c["id"]: c for c in MALFORMED + VALID}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # /s/<schema|none>/<case id>
        case = BY_ID[unquote(self.path.split("?")[0].rsplit("/", 1)[1])]
        body = case["body"].encode()
        self.send_response(case["status"])
        if case["content_type"]:
            self.send_header("content-type", case["content_type"])
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
