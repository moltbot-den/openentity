from conftest import SCHEMAS, load

from langchain_openentity import scrub
from langchain_openentity.core import compile_schema

V = load("vectors.json")


def test_scrub_vectors():
    for v in V["scrub"]:
        assert scrub("".join(v["in"])) == v["out"]
    assert "AKIA" not in scrub("x AKIAABCDEFGHIJKLMNOP y") and "keep" in scrub('{"api_key": "supersecretvalue", "name": "keep"}')


def test_schema_hashes_match_js():
    assert {k: compile_schema(v).hash for k, v in SCHEMAS.items()} == V["schema_hash"]
