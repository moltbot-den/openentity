import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from openentity import core


class Stub(BaseHTTPRequestHandler):
    """A tiny in-memory registry: just the routes the tools call. State lives on the class, reset per test."""
    entities: dict
    adopts: list

    def log_message(self, *a):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/v1/spec":
            return self._send(200, {"stamp_bits": 1})
        parts = path.split("/")  # "", v1, entities, eid, [record|attestations]
        e = self.entities.get(parts[3]) if len(parts) > 3 else None
        if not e:
            return self._send(404, {"error": "entity_not_found"})
        if len(parts) == 4:
            return self._send(200, {"eid": parts[3], "name": e["document"]["name"], "document": e["document"], "declaration": e["declaration"],
                                    "level": "L0", "withdrawn": False, "counts": {"record_entries": len(e["record"])}})
        if parts[4] == "attestations":
            return self._send(200, {"attestations": []})
        last = e["record"][-1] if e["record"] else None
        return self._send(200, {"eid": parts[3], "entries": e["record"],
                                "head": {"seq": last["seq"], "hash": core.canonical_hash(last).hex()} if last else None})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.path == "/v1/adopt":
            doc, decl = body["document"], body["declaration"]
            assert core.verify_object(doc)[0] and core.verify_object(decl)[0]
            self.adopts.append(body)
            self.entities[doc["eid"]] = {"document": doc, "declaration": decl, "record": []}
            return self._send(201, {"eid": doc["eid"], "level": "L0"})
        eid = self.path.split("/")[3]
        for entry in body["entries"]:
            assert core.verify_object(entry)[0]
            self.entities[eid]["record"].append(entry)
        return self._send(201, {"accepted": len(body["entries"])})


@pytest.fixture(autouse=True)
def registry(tmp_path, monkeypatch):
    """A local registry plus an empty identity home. Returns the Stub class (entities, adopts)."""
    Stub.entities, Stub.adopts = {}, []
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.setenv("OPENENTITY_KEYCHAIN", "off")
    monkeypatch.setenv("OPENENTITY_REGISTRY", f"http://127.0.0.1:{srv.server_port}")
    yield Stub
    srv.shutdown()
    srv.server_close()
