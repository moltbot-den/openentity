"""The shared corpus: every malformed response must raise, no valid one may."""

import pytest
from conftest import MALFORMED, SCHEMAS, VALID

from langchain_openentity import OpenEntitySchemaViolation, RuthlessSchemaGuard, inspect_response
from langchain_openentity.core import compile_schema

COMPILED = {k: compile_schema(v) for k, v in SCHEMAS.items()}


def guard():
    g = RuthlessSchemaGuard(scope="all")
    for name, schema in SCHEMAS.items():
        g.register(f"GET https://corpus.test/{name}", schema)
    return g


def run(g, case):
    url = f"https://corpus.test/{case['schema'] or 'free'}"
    g._check("GET", url, case["status"], case["content_type"], case["accept"], lambda: case["body"].encode())


def test_corpus_is_big_enough():
    assert len(MALFORMED) >= 200 and len(VALID) >= 200


@pytest.mark.parametrize("case", MALFORMED, ids=lambda c: c["id"])
def test_malformed_raises(case):
    errs = inspect_response(case["status"], case["content_type"], case["body"], COMPILED.get(case["schema"]), case["accept"])
    assert errs and errs[0].split(":")[0] == case["rule"]
    with pytest.raises(OpenEntitySchemaViolation) as e:
        run(guard(), case)
    assert e.value.rule == case["rule"] and len(e.value.raw_excerpt) <= 500


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["id"])
def test_valid_passes(case):
    assert inspect_response(case["status"], case["content_type"], case["body"], COMPILED.get(case["schema"]), case["accept"]) == []
    run(guard(), case)
