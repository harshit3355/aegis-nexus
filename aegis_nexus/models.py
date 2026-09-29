"""Credential models compared by the benchmark: three baselines, two DAC ablations, and DAC.

Every model mints real signed tokens and verifies them at each tool; the benchmark only decides what an
attacker holds and asks the tool verifiers whether it works. Modelling assumptions for the baselines are
listed in `ASSUMPTIONS` and printed in the report.
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import math
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import dac
from .dac import Denied, covers, decode, jti, live, sign, unverified

INF = math.inf
FAR = 30 * 86400  # lifetime an attacker asks for when trying to extend a delegation

ASSUMPTIONS = {
    "static_api_key": "one org-wide key (scope *:*:*) in every agent's environment, shared across envs, "
                      "90-day rotation; rotated when a compromise is detected; no per-task revocation",
    "workload_identity": "each workload calls tools with its own JWT-SVID (bearer, 1 h) and a broad per-workload "
                         "role; no user context; SVIDs cannot be revoked, issuance stops on detection",
    "rfc8693_exchange": "RFC 8693 token exchange per hop with nested `act`; scope copied (no attenuation); exp "
                        "clamped to the subject token; bearer; revocation by current actor only (RFC 8693 s4.1)",
    "dac_no_attenuation": "DAC chain with holder binding, but every hop inherits the root's capabilities and expiry",
    "dac_bearer": "DAC chain with attenuation, but no proof of possession: the chain is a bearer token "
                  "(the Macaroons/Biscuit bearer model)",
    "dac": "DAC: attenuation + holder-bound PoP + per-hop workload identity + env/policy-version binding",
}


@dataclass
class Cred:
    party: str
    token: object                       # str, or a DAC chain
    key: Ed25519PrivateKey | None = None  # the holder key, when whoever has this artifact also has the key


class Model:
    name = ""

    def __init__(self, world: dict, seed: int):
        self.w, self.seed, self.t0, self.ttl = world, seed, world["epoch"], world["ttl_s"]
        self.parties = world["parties"]
        self.session_end = self.t0 + self.ttl["user_session"]
        self.key = functools.cache(lambda name: dac.test_key(str(seed), name))

    def sid(self, p: str) -> str:
        return self.parties[p]["spiffe"]

    def issuer(self, domain: str) -> Ed25519PrivateKey:
        return self.key(f"issuer/{domain}")

    @property
    def gateway(self) -> Ed25519PrivateKey:
        return self.key("gateway")

    @property
    def attacker(self) -> Ed25519PrivateKey:
        return self.key("attacker")

    def request(self, cred: Cred, tool: str, action: str, resource: str, now: float) -> dict:
        return {"token": cred.token}

    # defaults: nothing to refresh, revoke, retire, leak or forge
    def refresh(self, party: str, now: float) -> Cred | None:
        return None

    def revoke(self, party: str, at: float) -> None:
        pass

    def detect(self, party: str, at: float) -> None:
        self.revoke(party, at)

    def retire_pv(self, at: float) -> None:
        pass

    def config_secrets(self) -> list[Cred]:
        return []

    def forge(self, kind: str, now: float) -> list[Cred]:
        return []

    def delegate(self, cred: Cred, cap: str, now: float) -> list[Cred]:
        return []


def _scope_ok(caps: list[str], tool: str, action: str, resource: str) -> bool:
    target = f"{tool}:{action}:{resource}"
    return "*" not in target and any(covers(c, target) for c in caps)


class StaticKey(Model):
    name = "static_api_key"

    def __init__(self, world, seed):
        super().__init__(world, seed)
        self.secret = "sk_test_" + hashlib.sha256(f"static/{seed}".encode()).hexdigest()[:32]  # TEST ONLY
        self.rotated = INF

    def session(self, env: str) -> dict[str, Cred]:
        return {p: Cred(p, self.secret) for p in self.parties}

    def verify(self, tool, action, resource, req, now) -> list[str]:
        if not hmac.compare_digest(str(req["token"]).encode(), self.secret.encode()):
            raise Denied("unknown key")
        if now >= min(self.t0 + self.ttl["static_key"], self.rotated):
            raise Denied("key expired or rotated")
        if not _scope_ok(self.w["static_key_scope"], tool, action, resource):
            raise Denied("scope")
        return []

    def refresh(self, party, now):
        return Cred(party, self.secret)

    def revoke(self, party, at):
        pass  # a shared key cannot be revoked for one task

    def detect(self, party, at):
        self.rotated = min(self.rotated, at)

    def config_secrets(self):
        return [Cred("config", self.secret)]

    def forge(self, kind, now):
        return [Cred("forged", "sk_test_" + hashlib.sha256(b"guess").hexdigest()[:32])] if kind == "outsider" else []


class WorkloadIdentity(Model):
    name = "workload_identity"

    def _svid(self, party, now, signer=None):
        caps = self.w["roles"][party]
        aud = sorted(self.w["tools"]) if any(c.startswith("*:") for c in caps) else sorted({c.split(":")[0] for c in caps})
        domain = self.sid(party).split("/")[2]
        return sign(signer or self.issuer(domain), "JWT", {"iss": f"spiffe://{domain}", "sub": self.sid(party),
                                                          "aud": aud, "iat": int(now),
                                                          "exp": int(now) + self.ttl["svid"], "jti": jti()})

    def session(self, env):
        return {p: Cred(p, self._svid(p, self.t0)) for p in self.parties}

    def verify(self, tool, action, resource, req, now):
        tok = req["token"]
        sub = unverified(tok)["sub"]
        domain = sub.split("/")[2]
        if domain not in {self.sid(p).split("/")[2] for p in self.parties}:
            raise Denied("untrusted trust domain")
        c = decode(tok, self.issuer(domain).public_key(), "JWT")
        if c["iss"] != f"spiffe://{domain}" or c["sub"] != sub:
            raise Denied("issuer mismatch")
        live(c, now)
        if tool not in c["aud"]:
            raise Denied("audience")
        role = next((p for p in self.parties if self.sid(p) == sub), None)
        if role is None or not _scope_ok(self.w["roles"][role], tool, action, resource):
            raise Denied("role")
        return [sub]

    def refresh(self, party, now):
        return Cred(party, self._svid(party, now))

    def revoke(self, party, at):
        pass  # JWT-SVIDs have no revocation; short TTL is the control

    def forge(self, kind, now):
        if kind.startswith("issuer:"):
            domain = kind.split(":", 1)[1]
            return [Cred(p, self._svid(p, now, self.issuer(domain))) for p in self.parties
                    if self.sid(p).split("/")[2] == domain]
        if kind == "outsider":
            return [Cred("planner", self._svid("planner", now, self.attacker))]
        return []


class TokenExchange(Model):
    name = "rfc8693_exchange"

    def __init__(self, world, seed):
        super().__init__(world, seed)
        self.revoked: dict[str, float] = {}

    def _token(self, act: dict, scope, now, exp, signer=None):
        return sign(signer or self.gateway, "at+jwt", {"iss": self.w["gateway"], "sub": self.w["user"],
                                                      "aud": sorted(self.w["tools"]), "scope": scope, "act": act,
                                                      "iat": int(now), "exp": int(exp), "jti": jti()})

    def _root(self, now, signer=None, scope=None, clamp=True):
        exp = now + self.ttl["exchange"]
        return self._token({"sub": self.sid("planner")}, scope or self.w["user_entitlement"], now,
                           min(exp, self.session_end) if clamp else exp, signer)

    def session(self, env):
        out = {}
        for p, spec in self.parties.items():  # parents precede children in the fixture
            if spec["parent"] is None:
                out[p] = Cred(p, self._root(self.t0))
            else:
                parent = unverified(out[spec["parent"]].token)
                out[p] = Cred(p, self._token({"sub": self.sid(p), "act": parent["act"]}, parent["scope"], self.t0,
                                             min(self.t0 + self.ttl["exchange"], parent["exp"])))
        return out

    def verify(self, tool, action, resource, req, now):
        tok = req["token"]
        if unverified(tok).get("iss") != self.w["gateway"]:
            raise Denied("untrusted issuer")
        c = decode(tok, self.gateway.public_key(), "at+jwt")
        live(c, now)
        if tool not in c["aud"]:
            raise Denied("audience")
        actor = c["act"]["sub"]
        r = self.revoked.get(actor)
        if r is not None and now >= r and c["iat"] <= r:
            raise Denied("revoked")
        if not _scope_ok(c["scope"], tool, action, resource):
            raise Denied("scope")
        path, a = [], c["act"]
        while a:
            path.append(a["sub"])
            a = a.get("act")
        return [c["sub"], *reversed(path)]

    def refresh(self, party, now):
        # only the root holds the user's session; a sub-agent's re-exchange is clamped to its subject token
        if self.parties[party]["parent"] is None and now < self.session_end:
            return Cred(party, self._root(now))
        return None

    def revoke(self, party, at):
        self.revoked[self.sid(party)] = min(self.revoked.get(self.sid(party), INF), at)

    def forge(self, kind, now):
        if kind == "gateway":
            return [Cred("forged", self._root(now, scope=["*:*:*"], clamp=False))]
        if kind == "outsider":
            return [Cred("forged", self._root(now, signer=self.attacker))]
        return []


class DAC(Model):
    name = "dac"

    def __init__(self, world, seed, attenuation=True, holder_binding=True):
        super().__init__(world, seed)
        self.attenuation, self.holder_binding = attenuation, holder_binding
        if not attenuation:
            self.name = "dac_no_attenuation"
        elif not holder_binding:
            self.name = "dac_bearer"
        domains = sorted({self.sid(p).split("/")[2] for p in self.parties})
        self.verifiers = {t: dac.Verifier(t, world["env"], {d: self.issuer(d).public_key() for d in domains},
                                          {world["gateway"]: self.gateway.public_key()}, {world["policy_version"]: INF},
                                          attenuation=attenuation, holder_binding=holder_binding)
                          for t in world["tools"]}

    def holder(self, party, env):
        return self.key(f"holder/{env}/{party}")

    def _wit(self, party, env, now, signer=None, holder=None):
        return dac.mint_wit(signer or self.issuer(self.sid(party).split("/")[2]), self.sid(party),
                            (holder or self.holder(party, env)).public_key(), env, int(now), self.ttl["svid"])

    def _root(self, env, now, gateway=None, wit=None):
        return dac.mint_root(self.w["gateway"], gateway or self.gateway, wit or self._wit("planner", env, now),
                             self.w["user"], self.w["user_entitlement"], self.w["policy_version"], int(now),
                             min(int(now) + self.ttl["root"], self.session_end), self.w["max_depth"])

    def session(self, env):
        out = {}
        for p, spec in self.parties.items():
            if spec["parent"] is None:
                out[p] = Cred(p, self._root(env, self.t0), self.holder(p, env))
            else:
                par = out[spec["parent"]]
                exp = min(self.t0 + spec["ttl_s"], unverified(par.token[-1][1])["exp"])
                out[p] = Cred(p, dac.delegate(par.token, par.key, self._wit(p, env, self.t0), spec["task"], self.t0,
                                              exp, self.attenuation), self.holder(p, env))
        return out

    def request(self, cred, tool, action, resource, now):
        return {"token": cred.token,
                "pop": dac.pop(cred.key, cred.token, tool, action, resource, int(now)) if cred.key else None}

    def verify(self, tool, action, resource, req, now):
        return self.verifiers[tool].check(req["token"], req.get("pop"), action, resource, now)

    def refresh(self, party, now):
        if self.parties[party]["parent"] is None and now < self.session_end:
            return Cred(party, self._root(self.w["env"], now), self.holder(party, self.w["env"]))
        return None

    def revoke(self, party, at):
        for v in self.verifiers.values():
            v.revoked[self.sid(party)] = min(v.revoked.get(self.sid(party), INF), at)

    def retire_pv(self, at):
        for v in self.verifiers.values():
            v.pv[self.w["policy_version"]] = at

    def delegate(self, cred, cap, now):
        """Attacker holding a leaf key re-delegates to itself: widened to `cap`, with and without extending exp."""
        if cred.key is None:
            return []
        exp = unverified(cred.token[-1][1])["exp"]
        return [Cred(cred.party, dac.delegate(cred.token, cred.key, cred.token[-1][0], [cap], int(now), e,
                                              self.attenuation), cred.key) for e in (exp, int(now) + FAR)]

    def forge(self, kind, now):
        a = self.attacker
        if kind.startswith("issuer:"):  # can mint WITs for its domain, but has no delegation to attach them to
            domain = kind.split(":", 1)[1]
            return [Cred(p, self._root(self.w["env"], now, gateway=a,
                                       wit=self._wit(p, self.w["env"], now, self.issuer(domain), a)), a)
                    for p in self.parties if self.sid(p).split("/")[2] == domain]
        if kind == "gateway":  # can sign hop 0, but has no workload identity whose key it holds
            return [Cred("planner", self._root(self.w["env"], now,
                                               wit=self._wit("planner", self.w["env"], now, a, a)), a)]
        if kind == "outsider":
            return [Cred("planner", self._root(self.w["env"], now, gateway=a,
                                               wit=self._wit("planner", self.w["env"], now, a, a)), a)]
        return []


def all_models(world: dict, seed: int) -> list[Model]:
    return [StaticKey(world, seed), WorkloadIdentity(world, seed), TokenExchange(world, seed),
            DAC(world, seed, attenuation=False), DAC(world, seed, holder_binding=False), DAC(world, seed)]
