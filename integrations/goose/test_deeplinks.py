"""The README deeplinks and the recipe describe the same endpoints, and every link is a valid goose extension link."""

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

HERE = Path(__file__).parent
RECIPE = yaml.safe_load((HERE / "openentity-stack.goose.yaml").read_text())
LINKS = re.findall(r"\]\((goose://extension\?[^)]+)\)", (HERE / "README.md").read_text())


def test_recipe_extensions_are_streamable_http_with_a_timeout():
    for e in RECIPE["extensions"]:
        assert e["type"] == "streamable_http" and e["uri"].startswith("https://") and e["timeout"] > 0


def test_header_keys_come_from_env_keys_never_inline():
    for e in RECIPE["extensions"]:
        for value in (e.get("headers") or {}).values():
            var = re.fullmatch(r"\$\{(\w+)\}", value)
            assert var and var.group(1) in e["env_keys"]


def test_every_recipe_endpoint_has_a_deeplink_with_the_same_url():
    urls = {parse_qs(urlparse(link).query)["url"][0] for link in LINKS}
    assert urls == {e["uri"] for e in RECIPE["extensions"]}


def test_links_carry_the_fields_goose_requires():
    assert len(LINKS) == 3
    for link in LINKS:
        q = parse_qs(urlparse(link).query)
        assert q["type"] == ["streamable_http"] and q["name"][0] and q["id"][0]
