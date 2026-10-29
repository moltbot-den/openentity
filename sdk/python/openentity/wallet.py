"""The wallet signer behind `--wallet` (PRD 7.2): secp256k1 EIP-191 personal_sign with a hex key or a key file.

The key is used for the one signature and never written anywhere."""
import os
import re
import secrets

from .core import _G, _N, _keccak, _mul

_KEY = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")


def checksum(addr: str) -> str:
    """EIP-55 checksum form of an address."""
    a = addr[2:].lower()
    h = _keccak(a).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


class Signer:
    def __init__(self, key_hex: str):
        self._d = int(key_hex.removeprefix("0x"), 16)
        if not 0 < self._d < _N:
            raise ValueError("not a valid secp256k1 private key")
        x, y = _mul(self._d, _G)
        self.address = checksum("0x" + _keccak(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex())

    def sign(self, message: str) -> str:
        """EIP-191 personal_sign, 0x-hex r || s || v."""
        m = message.encode()
        z = int.from_bytes(_keccak(f"\x19Ethereum Signed Message:\n{len(m)}".encode() + m), "big")
        while True:  # ponytail: random nonce (not RFC 6979); every signature is valid, only the bytes differ run to run
            x, y = _mul(k := secrets.randbelow(_N - 1) + 1, _G)
            r = x % _N
            s = pow(k, -1, _N) * (z + r * self._d) % _N
            if r and s:
                break
        v = y & 1
        if s > _N // 2:  # low-s, like every Ethereum signer
            s, v = _N - s, v ^ 1
        return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + format(27 + v, "02x")


def resolve_signer(spec: str | None, env=os.environ) -> Signer | None:
    """A hex key, or a file holding one; no `--wallet` falls back to OPENENTITY_WALLET_KEY. None for a bare address or did:pkh (declared, not proven)."""
    s = spec or env.get("OPENENTITY_WALLET_KEY")
    if not s:
        return None
    if _KEY.match(s):
        return Signer(s)
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", s) or s.startswith("did:pkh:"):
        return None
    try:
        text = open(s).read().strip()
    except OSError:
        raise ValueError("--wallet is not a hex private key, a wallet address, a did:pkh or a readable key file")
    if not _KEY.match(text):
        raise ValueError(f"{s} does not hold a 32-byte hex private key")
    return Signer(text)
