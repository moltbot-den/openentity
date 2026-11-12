"""Pairing match string (pair-sas/1): the four word pairs an agent prints and the owner's app shows when they pair.
Format and vectors: test-vectors/pair-sas-1/. The account service derives the same items for the app."""
import hashlib
import re

from .errors import InvalidInputError

_COLORS = "red orange yellow green blue purple pink brown black white gray gold silver navy olive coral".split()
_NOUNS = "fox kite bear boat star tree fish moon drum frog lamp owl wolf shell crown horse".split()
PAIR_SAS_WORDS = tuple(f"{_COLORS[i >> 4]} {_NOUNS[i & 15]}" for i in range(256))  # test-vectors/pair-sas-1/words.json


def pair_sas(code: str, agent_did: str) -> list[str]:
    """The four items for a pairing code (OE-XXXX-XXXX, any case) and the agent's DID: words[b] for each of the first 4 bytes
    of SHA-256("oe-pair-sas/1|CODE|did")."""
    c = str(code).strip().upper()
    if not re.fullmatch(r"OE-[0-9A-Z]{4}-[0-9A-Z]{4}", c):
        raise InvalidInputError("pairing code must look like OE-XXXX-XXXX")
    if not isinstance(agent_did, str) or not re.fullmatch(r"did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]", agent_did):
        raise InvalidInputError("agent_did must be a DID")
    return [PAIR_SAS_WORDS[b] for b in hashlib.sha256(f"oe-pair-sas/1|{c}|{agent_did}".encode()).digest()[:4]]
