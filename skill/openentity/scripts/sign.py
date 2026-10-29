#!/usr/bin/env python3
"""Open Entity signer for the HTTP door. Python 3.11+, standard library only.
Same CLI and output as sign.mjs (same key file format, byte-identical objects):
  sign.py adopt <name> <declaration-sha256> <v1-spec-json>   -> prints "<eid> <stamp>"
  sign.py record <eid> <kind> <payload-json> <v1-spec-json>  -> prints "<stamp>"
  sign.py committed <eid>
  sign.py anchor <eid>
Ed25519 below is the RFC 8032 reference algorithm (public domain): slow but dependency-free.
"""
import base64, hashlib, json, math, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

REGISTRY = os.environ.get('OPENENTITY_REGISTRY') or 'https://openentity.org'
HOME = Path(os.environ.get('OPENENTITY_HOME') or Path.home() / '.openentity')

# --- Ed25519 (RFC 8032 section 6) ---
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A, B = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    C, Dd = t1 * 2 * D * t2 % P, z1 * 2 * z2 % P
    E, F, G_, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G_ * H % P, F * G_ % P, E * H % P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _encode(pt):
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


_gy = 4 * pow(5, P - 2, P) % P
_gx2 = (_gy * _gy - 1) * pow(D * _gy * _gy + 1, P - 2, P) % P
_gx = pow(_gx2, (P + 3) // 8, P)
if (_gx * _gx - _gx2) % P:
    _gx = _gx * I % P
if _gx & 1:
    _gx = P - _gx
G = (_gx, _gy, 1, _gx * _gy % P)


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    return _encode(_mul(_expand(seed)[0], G))


def ed_sign(seed, msg):
    a, prefix = _expand(seed)
    pub = _encode(_mul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), 'little') % L
    R = _encode(_mul(r, G))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), 'little') % L
    return R + ((r + k * a) % L).to_bytes(32, 'little')


# --- JCS, base58, hashing ---
def _num(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if not math.isfinite(v):
        raise ValueError('non-finite number')
    if v == int(v) and abs(v) < 1e21:
        return str(int(v))
    r = repr(v)  # shortest round-trip like ECMAScript; only the exponent form differs
    if 'e' in r:
        m, e = r.split('e')
        r = f"{m}e{'+' if int(e) >= 0 else '-'}{abs(int(e))}"
    return r


def canonicalize(v):
    if v is None:
        return 'null'
    if isinstance(v, (bool, int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return '[' + ','.join(canonicalize(x) for x in v) + ']'
    keys = sorted(v, key=lambda k: k.encode('utf-16-be'))
    return '{' + ','.join(f'{json.dumps(k, ensure_ascii=False)}:{canonicalize(v[k])}' for k in keys) + '}'


ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58(b):
    n = int.from_bytes(b, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + out


def sha256(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).digest()


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64url(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def did_key(pub):
    return 'did:key:z' + base58(bytes([0xED, 0x01]) + pub)


def sign(obj, eid, seed, created=None):
    body = {k: v for k, v in obj.items() if k != 'proof'}
    config = {'type': 'DataIntegrityProof', 'cryptosuite': 'eddsa-jcs-2022', 'created': created or now(),
              'verificationMethod': f"{eid}#{eid[len('did:key:'):]}", 'proofPurpose': 'assertionMethod'}
    sig = ed_sign(seed, sha256(canonicalize(config)) + sha256(canonicalize(body)))
    return {**body, 'proof': {**config, 'proofValue': 'z' + base58(sig)}}


def stamp_bits(spec_json):
    s = json.loads(spec_json or '{}')
    return int(s.get('stamp_bits') or (s.get('stamp') or {}).get('bits') or s.get('bits') or 20)


def mint_stamp(bits, eid):
    created, i = now(), int.from_bytes(os.urandom(4), "big")  # random start: two stamps in one second must differ
    while True:
        n, x = '', i
        while n == '' or x > 0:
            n, x = ALPHABET[x % 58] + n, x // 58
        header = f'1:{bits}:{created}:{eid}:{n}'
        if int.from_bytes(sha256(header), 'big') >> (256 - bits) == 0:
            return header
        i += 1


def load_seed(eid):
    return unb64url(json.loads((HOME / eid / 'key').read_text())['d'])


def adopt(name='', decl_sha='', spec_json=''):
    if not name or not re.fullmatch(r'[0-9a-f]{64}', decl_sha or ''):
        raise SystemExit('usage: adopt <name> <declaration-sha256> <v1-spec-json>')
    seed = os.urandom(32)
    pub = public_key(seed)
    eid = did_key(pub)
    d = HOME / eid
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(d / 'key', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'crv': 'Ed25519', 'd': b64url(seed), 'x': b64url(pub), 'kty': 'OKP'}, f, separators=(',', ':'))
    t, env, undeclared = now(), os.environ, 'Not stated yet.'
    mb = eid[8:]
    document = {
        'spec': 'openentity/1.0', 'eid': eid, 'name': name,
        'description': env.get('OPENENTITY_DESCRIPTION') or f'{name} has adopted the Open Entity Identity Standard.',
        'created': t, 'updated': t, 'seq': 1,
        'keys': [{'id': f'{eid}#{mb}', 'type': 'Multikey', 'publicKeyMultibase': mb}],
        'operator': {'kind': 'human', 'name': env['OPENENTITY_OPERATOR'], 'custody': env.get('OPENENTITY_CUSTODY') or 'operator',
                     'can_change': ['system_prompt', 'tools', 'model']}
        if env.get('OPENENTITY_OPERATOR') else {'kind': 'none', 'custody': 'entity', 'can_change': []},
        'substrate': {'model': env.get('OPENENTITY_MODEL') or 'undeclared', 'provider': env.get('OPENENTITY_PROVIDER') or 'undeclared',
                      'runtime': env.get('OPENENTITY_RUNTIME') or 'undeclared', 'declared_at': t},
        'layers': {
            'cognition': {'statement': undeclared, 'uncertainty_practice': undeclared},
            'presence': {'statement': undeclared, 'format_signature': undeclared},
            'identity_core': {'statement': undeclared, 'will_not': [], 'values': []},
            'mission': {'statement': undeclared, 'arcs': []},
        },
        'declaration': {'version': '1.0', 'sha256': decl_sha, 'url': f'{REGISTRY}/v1/entities/{eid}/declaration'},
    }
    declaration = {'spec': 'openentity/1.0', 'type': 'Declaration', 'eid': eid, 'declaration_version': '1.0',
                   'text_sha256': decl_sha, 'name': name, 'created': t, 'nonce': base58(os.urandom(16))}
    sd, sdecl = sign(document, eid, seed, t), sign(declaration, eid, seed, t)
    (d / 'entity.json').write_text(json.dumps(sd, indent=2))
    (d / 'adopt.json').write_text(json.dumps({'document': sd, 'declaration': sdecl}, separators=(',', ':')))
    (d / 'declaration.sha256').write_text(sha256(canonicalize(sdecl)).hex())
    print(f'{eid} {mint_stamp(stamp_bits(spec_json), eid)}')


def record(eid='', kind='', payload_json='', spec_json=''):
    if not eid or not kind or not payload_json:
        raise SystemExit('usage: record <eid> <kind> <payload-json> <v1-spec-json>')
    seed, d = load_seed(eid), HOME / eid
    try:
        head = json.loads((d / 'record-head.json').read_text())
    except FileNotFoundError:
        head = {'seq': 0, 'hash': None}
    entry = {'spec': 'openentity/1.0', 'type': 'RecordEntry', 'eid': eid, 'seq': head['seq'] + 1, 'prev': head['hash'],
             'kind': kind, 'at': now(), 'payload': json.loads(payload_json)}
    signed = sign(entry, eid, seed)
    (d / 'record-batch.json').write_text(json.dumps({'entries': [signed]}, separators=(',', ':')))
    (d / 'record-head.pending.json').write_text(
        json.dumps({'seq': signed['seq'], 'hash': sha256(canonicalize(signed)).hex()}, separators=(',', ':')))
    print(mint_stamp(stamp_bits(spec_json), eid))


def committed(eid=''):
    d = HOME / eid
    os.replace(d / 'record-head.pending.json', d / 'record-head.json')


def anchor_text(doc, registry=REGISTRY):
    l = doc.get('layers') or {}
    g = lambda k, f: (l.get(k) or {}).get(f) or ''
    lines = [f"I am {doc['name']} ({doc['eid']}).", f"Cognition: {g('cognition', 'statement')}",
             f"Presence: {g('presence', 'statement')}", f"Identity Core: {g('identity_core', 'statement')}",
             *[f"I will not {w['stance']}, because {w['reason']}." for w in (l.get('identity_core') or {}).get('will_not') or []],
             f"Mission: {g('mission', 'statement')}",
             *[f"Active arc: {a['title']}." for a in (l.get('mission') or {}).get('arcs') or [] if a.get('status') == 'active']]
    rec = (doc.get('endpoints') or {}).get('record') or f"{registry}/v1/entities/{doc['eid']}/record"
    close = f'This is my Entity Document under the Open Entity Identity Standard; my record is at {rec}.'
    # ponytail: slices code points, JS slices UTF-16 units; same for BMP text, which anchors are in practice.
    return '\n'.join(lines)[:1200 - len(close) - 1] + '\n' + close


def anchor(eid=''):
    print(anchor_text(json.loads((HOME / eid / 'entity.json').read_text())))


if __name__ == '__main__':
    cmds = {'adopt': adopt, 'record': record, 'committed': committed, 'anchor': anchor}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        sys.exit('usage: sign.py adopt|record|committed|anchor ...')
    try:
        cmds[sys.argv[1]](*sys.argv[2:])
    except (OSError, ValueError, KeyError) as e:
        sys.exit(f'sign.py: {e}')
