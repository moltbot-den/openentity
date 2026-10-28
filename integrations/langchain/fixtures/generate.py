"""Regenerates the shared corpus: schemas.json, malformed.json, valid.json, vectors.json.

Run from integrations/langchain/python:  uv run python ../fixtures/generate.py
Deterministic. It asserts its own expectations against the Python implementation, so a rule change
that breaks the corpus fails here before it fails in the test suites.
"""

import copy
import json
import pathlib

from langchain_openentity.core import compile_schema, inspect_response, scrub

OUT = pathlib.Path(__file__).parent
S = {
    "pull_list": {"type": "array", "items": {
        "type": "object", "required": ["number", "title", "state", "user"],
        "properties": {"number": {"type": "integer"}, "title": {"type": "string"},
                       "state": {"enum": ["open", "closed"]}, "draft": {"type": "boolean"},
                       "merged_at": {"type": ["string", "null"]},
                       "user": {"type": "object", "required": ["login"], "properties": {"login": {"type": "string"}}}}}},
    "repo": {"type": "object", "required": ["id", "name", "private", "stargazers_count"],
             "properties": {"id": {"type": "integer"}, "name": {"type": "string"}, "private": {"type": "boolean"},
                            "stargazers_count": {"type": "integer", "minimum": 0},
                            "description": {"type": ["string", "null"]}}},
    "user": {"type": "object", "required": ["id", "login", "created_at"],
             "properties": {"id": {"type": "integer"}, "login": {"type": "string", "minLength": 1},
                            "email": {"type": ["string", "null"]}, "created_at": {"type": "string"}}},
    "search": {"type": "object", "required": ["total_count", "items"],
               "properties": {"total_count": {"type": "integer"}, "items": {"type": "array", "items": {
                   "type": "object", "required": ["id", "score"],
                   "properties": {"id": {"type": "integer"}, "score": {"type": "number"}}}}}},
    "job": {"type": "object", "required": ["id", "state"],
            "properties": {"id": {"type": "string"}, "state": {"enum": ["queued", "running", "done", "failed"]},
                           "error": {"type": ["string", "null"]}}},
    "tags": {"type": "array", "items": {"type": "string"}},
    "count": {"type": "integer"},
    "flag": {"type": "object", "required": ["success"], "properties": {"success": {"type": "boolean"}}},
}
SC = {k: compile_schema(v) for k, v in S.items()}

VALID_DOCS = {
    "pull_list": [
        [], [{"number": 1, "title": "Fix", "state": "open", "user": {"login": "a"}}],
        [{"number": 7, "title": "Émoji \U0001F680 title", "state": "closed", "draft": False, "merged_at": "2026-01-02T03:04:05Z", "user": {"login": "b", "id": 3}}],
        [{"number": 2, "title": "", "state": "open", "merged_at": None, "user": {"login": "c"}, "extra": {"x": [1, 2]}},
         {"number": 3, "title": "t", "state": "closed", "user": {"login": "d"}}],
        [{"number": 9007199254740991, "title": "big", "state": "open", "user": {"login": "e"}}],
    ],
    "repo": [
        {"id": 1, "name": "r", "private": False, "stargazers_count": 0},
        {"id": 2, "name": "r2", "private": True, "stargazers_count": 12, "description": None},
        {"id": 3, "name": "r3", "private": False, "stargazers_count": 5, "description": "A <b>bold</b> repo with \"quotes\""},
        {"id": 4, "name": "naïve", "private": False, "stargazers_count": 1, "description": "line1\nline2", "topics": []},
    ],
    "user": [
        {"id": 1, "login": "x", "created_at": "2020-01-01"},
        {"id": 2, "login": "y", "email": None, "created_at": "2020-01-01T00:00:00Z"},
        {"id": 3, "login": "z", "email": "z@example.com", "created_at": "t", "bio": "<html> in a string"},
    ],
    "search": [
        {"total_count": 0, "items": []},
        {"total_count": 2, "items": [{"id": 1, "score": 1.5}, {"id": 2, "score": 3}]},
        {"total_count": 1, "items": [{"id": 5, "score": 0.0001, "name": "n"}], "incomplete_results": False},
    ],
    "job": [
        {"id": "j1", "state": "queued"}, {"id": "j2", "state": "running", "error": None},
        {"id": "j3", "state": "failed", "error": "boom"}, {"id": "j4", "state": "done", "error": ""},
    ],
    "tags": [[], ["a"], ["a", "b", "c"], ["<html>", "callback(1)", "{\"x\":1}"]],
    "count": [0, 1, 42, 123456789012],
    "flag": [{"success": True}, {"success": False}, {"success": True, "note": "ok"}],
}


def dump(v, style):
    if style == "pretty":
        return json.dumps(v, indent=2, ensure_ascii=False)
    if style == "ascii":
        return json.dumps(v)
    if style == "padded":
        return "\n  " + json.dumps(v, separators=(",", ":")) + "\r\n\t "
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def mk(id, body, schema=None, status=200, ct="application/json", accept="", rule=None):
    c = {"id": id, "status": status, "content_type": ct, "accept": accept, "schema": schema, "body": body}
    if rule:
        c["rule"] = rule
    return c


# ---------------------------------------------------------------- valid
valid = []
CTS = ["application/json", "application/json; charset=utf-8", "application/vnd.api+json", "application/problem+json", "text/json"]
n = 0
for name, docs in VALID_DOCS.items():
    for i, doc in enumerate(docs):
        for j, style in enumerate(["compact", "pretty", "ascii", "padded"]):
            valid.append(mk(f"v-{name}-{i}-{style}", dump(doc, style), name, ct=CTS[(i + j) % len(CTS)]))
        valid.append(mk(f"v-{name}-{i}-201", dump(doc, "compact"), name, status=201))
        valid.append(mk(f"v-{name}-{i}-nocase", dump(doc, "compact"), name, ct="Application/JSON"))
# no schema: JSON by content type or Accept header; envelope-looking but benign
for i, doc in enumerate([{}, [], None, "str", 123, 1.5, True, False, {"error": None}, {"errors": []}, {"error": ""}, {"error": 0},
                         {"error": False}, {"errors": {}}, {"success": True}, {"ok": True}, {"data": {"error": "nested is fine"}},
                         {"items": [{"error": "inner"}]}, {"message": "<html></html>"}, {"a": {"b": {"c": [1, {"d": None}]}}},
                         {"text": "callback({\"x\":1})"}, {"unicode": "☃ \U0001F600"}, [1, 2, 3], ["a", None, 1.5]]):
    valid.append(mk(f"v-free-ct-{i}", dump(doc, "compact")))
    valid.append(mk(f"v-free-accept-{i}", dump(doc, "pretty"), ct="text/plain", accept="application/json"))
# not inspected: not a 2xx JSON response
for i, (st, ct, body) in enumerate([
    (204, "application/json", ""), (205, "application/json", ""), (204, "", ""),
    (404, "text/html", "<html>Not Found</html>"), (500, "application/json", ""), (502, "text/html", "<h1>Bad Gateway</h1>"),
    (429, "application/json", "{\"error\":\"rate limited\"}"), (401, "application/json", "{\"errors\":[{\"message\":\"no\"}]}"),
    (301, "text/html", "<a href=\"/x\">moved</a>"), (304, "", ""), (400, "application/json", "not json"),
    (503, "text/plain", "upstream unavailable"), (418, "application/json", "{\"error\":\"teapot\"}"),
]):
    valid.append(mk(f"v-skip-status-{i}", body, "repo" if i % 2 else None, status=st, ct=ct))
for i, (ct, body) in enumerate([
    ("text/html", "<!doctype html><html><body>a page</body></html>"), ("text/html; charset=utf-8", "<html></html>"),
    ("text/plain", "plain text"), ("text/plain", ""), ("text/csv", "a,b\n1,2\n"), ("application/xml", "<?xml version=\"1.0\"?><a/>"),
    ("application/pdf", "%PDF-1.4"), ("image/png", "�PNG"), ("text/event-stream", "data: {\"x\":\n\ndata: [DONE]\n\n"),
    ("application/x-ndjson", "{\"a\":1}\n{\"b\":2}\n"), ("application/jsonl", "{\"a\":1}\n"), ("application/octet-stream", "\x00\x01"),
    ("text/css", "body{}"), ("application/javascript", "callback({\"x\":1})"), ("", "<html>no content type</html>"),
    ("text/markdown", "# title"), ("application/yaml", "a: 1"), ("text/html", ""),
]):
    valid.append(mk(f"v-notjson-{i}", body, None, ct=ct))
# ignore-listed scalar with schema
valid.append(mk("v-count-pad", " 7 ", "count"))
valid.append(mk("v-count-neg", "-3", "count"))
valid.append(mk("v-count-float-int", "5.0", "count"))
valid.append(mk("v-tags-nested-quote", "[\"a\\\"b\",\"\\\\\"]", "tags"))
valid.append(mk("v-job-failed-error-declared", "{\"id\":\"j\",\"state\":\"failed\",\"error\":\"declared field\"}", "job"))
valid.append(mk("v-flag-false-declared", "{\"success\":false}", "flag"))

# ---------------------------------------------------------------- malformed
bad = []
HTML = ["<!doctype html><html><head><title>Login</title></head><body>Sign in</body></html>", "<html><body><h1>502 Bad Gateway</h1></body></html>",
        "<!DOCTYPE html>\n<html lang=\"en\"><body>Just a moment...</body></html>", "<HTML><HEAD><TITLE>Error</TITLE></HEAD></HTML>",
        "\n\n  <html>cloudflare challenge</html>", "<body>Access denied</body>", "<div id=\"root\"></div>", "<!-- cache --><html></html>",
        "<h1>Welcome to nginx!</h1>", "<script>window.location='/login'</script>"]
for i, b in enumerate(HTML):
    bad.append(mk(f"m-html-{i}-schema", b, ["pull_list", "repo", "user", "search", "job"][i % 5], rule="html"))
    bad.append(mk(f"m-html-{i}-ctjson", b, rule="html"))
    bad.append(mk(f"m-html-{i}-accept", b, ct="text/html; charset=utf-8", accept="application/json", rule="html"))
XML = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code></Error>", "<?XML version=\"1.0\"?><a/>",
       "<rss version=\"2.0\"><channel/></rss>", "<soap:Envelope><soap:Body/></soap:Envelope>", "<Error><Message>nope</Message></Error>"]
for i, b in enumerate(XML):
    bad.append(mk(f"m-xml-{i}-schema", b, "repo", ct="application/xml", rule="xml"))
    bad.append(mk(f"m-xml-{i}-ctjson", b, ct="application/json", rule="html" if not b.startswith("<?") else "xml"))
    bad.append(mk(f"m-xml-{i}-accept", b, ct="text/xml", accept="application/json", rule="xml"))
for i, b in enumerate(["", " ", "\n", "\r\n\t ", "   \n   "]):
    bad.append(mk(f"m-empty-{i}-schema", b, ["tags", "repo", "user", "job", "search"][i], rule="empty"))
    bad.append(mk(f"m-empty-{i}-ct", b, rule="empty"))
    bad.append(mk(f"m-empty-{i}-202", b, ct="text/plain", accept="application/json", status=202, rule="empty"))
for i, (name, docs) in enumerate(VALID_DOCS.items()):
    for j, doc in enumerate(docs[:2]):
        bad.append(mk(f"m-bom-{name}-{j}", "﻿" + dump(doc, "compact"), name, rule="bom"))
        bad.append(mk(f"m-bom-{name}-{j}-free", "﻿" + dump(doc, "pretty"), rule="bom"))
JSONP = ["callback({\"a\":1});", "cb([1,2,3])", "jQuery123_456({\"ok\":true});", "window.cb({\"a\":1})", "  handle ( {\"a\":1} ) ;",
         "$.cb({})", "_x({\"a\":[]})", ")]}'\n{\"a\":1}", ")]}',\n[1,2]", "while(1);{\"a\":1}", "for(;;);{\"a\":1}", "angular.callbacks._0({\"a\":1})"]
for i, b in enumerate(JSONP):
    rule = "jsonp"
    bad.append(mk(f"m-jsonp-{i}-schema", b, ["repo", "user", "search", "job"][i % 4], rule=rule))
    bad.append(mk(f"m-jsonp-{i}-ct", b, rule=rule))
for name, docs in VALID_DOCS.items():
    for j, doc in enumerate(docs):
        full = dump(doc, "compact")
        if len(full) < 4 or not isinstance(doc, (dict, list)):
            continue
        for frac in (0.3, 0.7, 0.95):
            cut = max(1, int(len(full) * frac))
            if cut >= len(full):
                cut = len(full) - 1
            bad.append(mk(f"m-trunc-{name}-{j}-{int(frac * 100)}", full[:cut], name, rule="truncated"))
for i, b in enumerate(["{'a': 1}", "{\"a\": 1,}", "[1,2,]", "{a: 1}", "{\"a\": NaN}", "{\"a\": Infinity}", "{\"a\": undefined}", "OK",
                       "Internal Server Error", "{\"a\":1}}", "{\"a\":1}{\"b\":2}", "[1] [2]", "{\"a\" 1}", "True", "none", "{\"a\": 01}",
                       "{\"a\":\"line\nbreak\"}", "{\"a\": .5}", "\"unterminated", "}{"]):
    r = "truncated" if b == "\"unterminated" else "invalid_json"
    bad.append(mk(f"m-invalid-{i}-ct", b, rule=r))
    bad.append(mk(f"m-invalid-{i}-schema", b, ["repo", "job", "user", "tags"][i % 4], rule=r))
ENV = ["{\"error\":\"rate limited\"}", "{\"error\":{\"code\":500,\"message\":\"boom\"}}", "{\"errors\":[{\"message\":\"bad\"}]}",
       "{\"success\":false,\"message\":\"denied\"}", "{\"ok\":false,\"error\":\"nope\"}", "{\"error\":true}", "{\"errors\":{\"field\":\"x\"}}",
       "{\"data\":null,\"errors\":[{\"message\":\"graphql\"}]}", "{\"error\":\"Not Found\",\"status\":404}", "{\"ok\":false}", "{\"success\":false}",
       "{\"error\":\"x\",\"id\":1,\"name\":\"n\",\"private\":false,\"stargazers_count\":1}"]
for i, b in enumerate(ENV):
    bad.append(mk(f"m-env-{i}-ct", b, rule="error_envelope"))
    bad.append(mk(f"m-env-{i}-accept", b, ct="text/plain", accept="application/json", rule="error_envelope"))
    if i != 10:  # {"success":false} is declared by the flag schema, so it is not an envelope there
        bad.append(mk(f"m-env-{i}-schema", b, ["repo", "user", "search", "tags"][i % 4] if i not in (3, 4, 9) else "repo", rule="error_envelope"))


def mutate(doc, how):
    d = copy.deepcopy(doc)
    first = d[0] if isinstance(d, list) and d else d
    if how == "drop_required":
        key = list(first)[0]
        del first[key]
    elif how == "int_to_str":
        k = next(k for k, v in first.items() if isinstance(v, int) and not isinstance(v, bool))
        first[k] = str(first[k])
    elif how == "str_to_int":
        k = next(k for k, v in first.items() if isinstance(v, str))
        first[k] = 7
    elif how == "null_required":
        first[list(first)[0]] = None
    elif how == "bool_to_str":
        k = next(k for k, v in first.items() if isinstance(v, bool))
        first[k] = "false"
    return d


for name in ("pull_list", "repo", "user", "search", "job"):
    for j, doc in enumerate(VALID_DOCS[name]):
        base = doc[0] if isinstance(doc, list) and doc else doc
        if isinstance(doc, list) and not doc:
            continue
        for how in ("drop_required", "int_to_str", "str_to_int", "null_required", "bool_to_str"):
            try:
                m = mutate(doc, how)
            except StopIteration:
                continue
            if m == doc or not SC[name].validate(m, ""):  # skip mutations the schema does not constrain
                continue
            bad.append(mk(f"m-schema-{name}-{j}-{how}", dump(m, "compact"), name, rule="schema"))
# whole-shape drift
for i, (name, b) in enumerate([
    ("pull_list", "{\"number\":1}"), ("pull_list", "[1,2]"), ("pull_list", "\"none\""), ("pull_list", "null"), ("pull_list", "[{\"number\":1,\"title\":\"t\",\"state\":\"merged\",\"user\":{\"login\":\"a\"}}]"),
    ("pull_list", "[{\"number\":1,\"title\":\"t\",\"state\":\"open\",\"user\":\"a\"}]"), ("pull_list", "[{\"number\":1.5,\"title\":\"t\",\"state\":\"open\",\"user\":{\"login\":\"a\"}}]"),
    ("repo", "[]"), ("repo", "null"), ("repo", "{}"), ("repo", "{\"id\":1,\"name\":\"r\",\"private\":false,\"stargazers_count\":-1}"), ("repo", "{\"id\":true,\"name\":\"r\",\"private\":false,\"stargazers_count\":1}"),
    ("user", "{\"id\":1,\"login\":\"\",\"created_at\":\"t\"}"), ("user", "[]"), ("search", "{\"total_count\":1,\"items\":{}}"), ("search", "{\"total_count\":1,\"items\":[{\"id\":1,\"score\":\"high\"}]}"),
    ("job", "{\"id\":\"j\",\"state\":\"DONE\"}"), ("job", "{\"id\":5,\"state\":\"done\"}"), ("tags", "[1,2]"), ("tags", "{\"a\":\"b\"}"), ("tags", "[\"a\",null]"),
    ("count", "\"42\""), ("count", "4.5"), ("count", "null"), ("count", "[42]"), ("count", "true"), ("flag", "{\"success\":\"true\"}"), ("flag", "{}"), ("flag", "[]"),
]):
    bad.append(mk(f"m-shape-{i}-{name}", b, name, rule="schema"))

assert len(bad) >= 200 and len(valid) >= 200, (len(bad), len(valid))
ids = [c["id"] for c in bad + valid]
assert len(ids) == len(set(ids)), "duplicate ids"
for c in bad:
    errs = inspect_response(c["status"], c["content_type"], c["body"], SC.get(c["schema"]), c["accept"])
    assert errs and errs[0].split(":")[0] == c["rule"], (c["id"], c["rule"], errs)
for c in valid:
    errs = inspect_response(c["status"], c["content_type"], c["body"], SC.get(c["schema"]), c["accept"])
    assert not errs, (c["id"], errs)

# scrub and hash vectors
scrub_in = [
    "token AKIAABCDEFGHIJKLMNOP end", "ghp_" + "a" * 36, "xoxb-123-abcDEF", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    "{\"api_key\": \"supersecretvalue\", \"name\": \"keep\"}", "password=hunter22 other=ok", "postgres://user:pw@db.example.com:5432/app",
    "https://bob:s3cret@example.com/path", "sk_live_" + "A1" * 12, "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
    "nothing secret here", "{\"title\":\"a token of appreciation\"}",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig_nature-123",
]
vectors = {
    # inputs are stored in two halves so push protection does not mistake the fake secrets for real ones
    "scrub": [{"in": [s[: len(s) // 2], s[len(s) // 2 :]], "out": scrub(s)} for s in scrub_in],
    "schema_hash": {k: v.hash for k, v in SC.items()},
}
for out, data in (("schemas.json", S), ("malformed.json", bad), ("valid.json", valid), ("vectors.json", vectors)):
    (OUT / out).write_text(json.dumps(data, indent=1, ensure_ascii=False, sort_keys=out in ("schemas.json", "vectors.json")) + "\n")
print(f"malformed={len(bad)} valid={len(valid)}")
