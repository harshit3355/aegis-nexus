"""Delegation Attestation Chain (DAC): the mechanism.

A chain is a list of hops ``(wit, link)``:

- ``wit``: workload identity token (WIMSE WIT-style JWT): SPIFFE ID, environment and the workload's
  public key (``cnf``), signed by the issuer of the workload's own trust domain (one per cloud).
- ``link``: delegation token. Hop 0 is signed by the delegation gateway (user consent + policy decision);
  hop i > 0 is signed by the *holder key of hop i-1*. It carries the on-behalf-of principal, capabilities,
  environment, policy version, expiry, depth, the hash of its parent link and the hash of its holder's WIT.

The leaf holder proves possession with a per-request PoP JWT bound to tool, action, resource and the leaf.
The link invariants follow draft-niyikiza-oauth-attenuating-agent-tokens (cnf, par_hash, del_depth,
monotone exp and capabilities); the per-hop WIT binding and env/policy-version fields are this project's.

All signing and verification is PyJWT over `cryptography` Ed25519. Keys are TEST ONLY (see `test_key`).
Clock values are simulated epoch seconds passed in explicitly, so PyJWT's wall-clock checks are disabled
and every time check is done here.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import secrets
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ALG = "EdDSA"
SKEW = 5          # seconds of tolerated clock skew for iat
POP_WINDOW = 60   # a PoP proof is accepted for this many seconds after its iat
MAX_HOPS = 8
PV_RETIRED = "retired"


class Denied(Exception):
    pass


def test_key(seed: str, name: str) -> Ed25519PrivateKey:
    """TEST-ONLY key derived from a public seed so runs are reproducible. Never use outside this simulator."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"aegis-test/{seed}/{name}".encode()).digest())


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def jwk(pub: Ed25519PublicKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw(pub))}


def pub_from_jwk(j: dict) -> Ed25519PublicKey:
    if j.get("kty") != "OKP" or j.get("crv") != "Ed25519":
        raise Denied("unsupported cnf key")
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(j["x"] + "=" * (-len(j["x"]) % 4)))


def thumbprint(j: dict) -> str:
    """RFC 7638 JWK thumbprint, as a URN (RFC 9278)."""
    canon = json.dumps({k: j[k] for k in ("crv", "kty", "x")}, separators=(",", ":"), sort_keys=True)
    return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + _b64(hashlib.sha256(canon.encode()).digest())


def digest(token: str) -> str:
    return _b64(hashlib.sha256(token.encode()).digest())


def jti() -> str:
    return secrets.token_urlsafe(12)


def sign(key: Ed25519PrivateKey, typ: str, claims: dict) -> str:
    return jwt.encode(claims, key, algorithm=ALG, headers={"typ": typ})


@functools.lru_cache(maxsize=1 << 16)
def _verified(token: str, pub_raw: bytes, typ: str) -> str:
    # ponytail: memoised because the benchmark re-verifies the same links millions of times; the result is a
    # pure function of (token, key, typ). Returns JSON so callers cannot mutate a cached value.
    try:
        if jwt.get_unverified_header(token).get("typ") != typ:
            raise Denied(f"{typ}: wrong typ")
        claims = jwt.decode(token, Ed25519PublicKey.from_public_bytes(pub_raw), algorithms=[ALG],
                            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False,
                                     "verify_aud": False, "require": ["iat", "exp", "jti"]})
    except jwt.PyJWTError as e:
        raise Denied(f"{typ}: {e}") from None
    return json.dumps(claims)


def decode(token: str, pub: Ed25519PublicKey, typ: str) -> dict:
    return json.loads(_verified(token, raw(pub), typ))


def unverified(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def live(c: dict, now: float) -> None:
    if not (isinstance(c["iat"], int) and isinstance(c["exp"], int)):
        raise Denied("non-integer time claim")
    if c["iat"] > now + SKEW:
        raise Denied("issued in the future")
    if now >= c["exp"]:
        raise Denied("expired")


# --- capabilities: "tool:action:resource", resource may end in "*" (prefix); "*" alone matches anything ---

def covers(p: str, c: str) -> bool:
    pt, pa, pr = p.split(":", 2)
    ct, ca, cr = c.split(":", 2)
    return pt in ("*", ct) and pa in ("*", ca) and (pr == cr or (pr.endswith("*") and cr.startswith(pr[:-1])))


def attenuates(parent: list[str], child: list[str]) -> bool:
    return all(any(covers(p, c) for p in parent) for c in child)


def valid_caps(caps) -> bool:
    return isinstance(caps, list) and bool(caps) and all(isinstance(c, str) and c.count(":") >= 2 for c in caps)


# --- minting ---

def mint_wit(issuer: Ed25519PrivateKey, spiffe_id: str, holder: Ed25519PublicKey, env: str, now: int, ttl: int) -> str:
    domain = spiffe_id.split("/")[2]
    return sign(issuer, "wit+jwt", {"iss": f"spiffe://{domain}", "sub": spiffe_id, "env": env,
                                    "cnf": {"jwk": jwk(holder)}, "iat": now, "exp": now + ttl, "jti": jti()})


def mint_root(gateway_id: str, gateway: Ed25519PrivateKey, wit: str, obo: str, cap: list[str], pv: str,
              now: int, exp: int, max_depth: int) -> list[tuple[str, str]]:
    """Gateway issues hop 0 to the workload named by `wit` (which it is assumed to have verified)."""
    w = unverified(wit)
    link = sign(gateway, "dac+jwt", {"iss": gateway_id, "sub": w["sub"], "obo": obo, "cap": cap, "env": w["env"],
                                     "pv": pv, "iat": now, "exp": min(exp, w["exp"]), "jti": jti(),
                                     "del_depth": 0, "del_max_depth": max_depth, "wit_hash": digest(wit),
                                     "cnf": w["cnf"]})
    return [(wit, link)]


def delegate(chain: list[tuple[str, str]], holder: Ed25519PrivateKey, child_wit: str, cap: list[str] | None,
             now: int, exp: int, attenuate: bool = True) -> list[tuple[str, str]]:
    """Holder of the chain's leaf appends a hop for `child_wit` with the given capabilities and expiry (the
    caller decides; the verifier enforces). With attenuate=False the child inherits the parent's capabilities
    and expiry unchanged (the ablation)."""
    parent_raw = chain[-1][1]
    p, w = unverified(parent_raw), unverified(child_wit)
    link = sign(holder, "dac+jwt", {
        "iss": thumbprint(p["cnf"]["jwk"]), "sub": w["sub"], "obo": p["obo"],
        "cap": cap if attenuate else p["cap"], "env": p["env"], "pv": p["pv"], "iat": now,
        "exp": exp if attenuate else p["exp"], "jti": jti(), "del_depth": p["del_depth"] + 1,
        "par_hash": digest(parent_raw), "wit_hash": digest(child_wit), "cnf": w["cnf"]})
    return [*chain, (child_wit, link)]


def pop(holder: Ed25519PrivateKey, chain: list[tuple[str, str]], tool: str, action: str, resource: str, now: int) -> str:
    return sign(holder, "pop+jwt", {"htu": tool, "htm": action, "res": resource, "ath": digest(chain[-1][1]),
                                    "iat": now, "exp": now + POP_WINDOW, "jti": jti()})


# --- verification (runs at each tool) ---

@dataclass
class Verifier:
    tool: str
    env: str
    trust: dict[str, Ed25519PublicKey]       # trust domain -> WIT issuer key (one per cloud)
    gateways: dict[str, Ed25519PublicKey]    # gateway id -> key
    pv: dict[str, float]                     # accepted policy version -> time it is retired (inf = current)
    revoked: dict[str, float] = field(default_factory=dict)  # SPIFFE ID -> t: links it held issued <= t die at t
    seen: set[str] = field(default_factory=set)  # PoP jti replay cache. ponytail: unbounded; expire by iat+window at scale
    attenuation: bool = True
    holder_binding: bool = True

    def check(self, chain, proof: str | None, action: str, resource: str, now: float) -> list[str]:
        """Return the audit path [principal, hop0 workload, ...]; raise Denied on any failure (fail closed)."""
        try:
            return self._check(chain, proof, action, resource, now)
        except Denied:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
            raise Denied(f"malformed: {type(e).__name__}") from None

    def _check(self, chain, proof, action, resource, now):
        if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_HOPS:
            raise Denied("bad chain length")
        root = parent = parent_raw = None
        path = []
        for i, (wit_raw, link_raw) in enumerate(chain):
            sub = unverified(wit_raw)["sub"]
            domain = sub.split("/")[2] if sub.startswith("spiffe://") else None
            if domain not in self.trust:
                raise Denied("untrusted trust domain")
            wit = decode(wit_raw, self.trust[domain], "wit+jwt")
            if wit["iss"] != f"spiffe://{domain}" or wit["sub"] != sub:
                raise Denied("wit issuer does not own the SPIFFE ID")
            live(wit, now)
            if i == 0:
                if unverified(link_raw)["iss"] not in self.gateways:
                    raise Denied("untrusted gateway")
                link = decode(link_raw, self.gateways[unverified(link_raw)["iss"]], "dac+jwt")
                if link["del_depth"] != 0:
                    raise Denied("root depth")
                root = link
            else:
                link = decode(link_raw, pub_from_jwk(parent["cnf"]["jwk"]), "dac+jwt")
                if link["iss"] != thumbprint(parent["cnf"]["jwk"]):
                    raise Denied("issuer is not the parent holder")
                if link.get("par_hash") != digest(parent_raw):
                    raise Denied("parent hash mismatch (splice)")
                if link["del_depth"] != parent["del_depth"] + 1 or link["del_depth"] > root["del_max_depth"]:
                    raise Denied("depth")
                if any(link[k] != root[k] for k in ("obo", "env", "pv")):
                    raise Denied("principal/env/policy changed mid-chain")
                if self.attenuation and link["exp"] > parent["exp"]:
                    raise Denied("lifetime extension")
                if self.attenuation and not (valid_caps(link["cap"]) and attenuates(parent["cap"], link["cap"])):
                    raise Denied("capability widening")
            live(link, now)
            if link["sub"] != wit["sub"] or link["cnf"] != wit["cnf"] or link["wit_hash"] != digest(wit_raw):
                raise Denied("link not bound to this workload identity")
            if wit["env"] != self.env or link["env"] != self.env:
                raise Denied("wrong environment")
            r = self.revoked.get(link["sub"])
            if r is not None and now >= r and link["iat"] <= r:
                raise Denied("revoked")
            parent, parent_raw = link, link_raw
            path.append(link["sub"])
        if now >= self.pv.get(root["pv"], -1):
            raise Denied("policy version not accepted")
        target = f"{self.tool}:{action}:{resource}"
        caps = parent["cap"] if self.attenuation else root["cap"]
        if "*" in target or not valid_caps(caps) or not any(covers(c, target) for c in caps):
            raise Denied("capability not granted")
        if self.holder_binding:
            if not proof:
                raise Denied("missing proof of possession")
            p = decode(proof, pub_from_jwk(parent["cnf"]["jwk"]), "pop+jwt")
            if (p.get("htu"), p.get("htm"), p.get("res")) != (self.tool, action, resource):
                raise Denied("proof bound to another request")
            if p.get("ath") != digest(parent_raw):
                raise Denied("proof bound to another token")
            if not isinstance(p["iat"], int) or p["iat"] > now + SKEW or now - p["iat"] > POP_WINDOW:
                raise Denied("stale proof")
            if p["jti"] in self.seen:
                raise Denied("replayed proof")
            self.seen.add(p["jti"])
        return [root["obo"], *path]
