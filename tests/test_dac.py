"""Negative tests: every check in dac.Verifier, each with an attack that only that check stops."""
import jwt
import pytest

from aegis_nexus import dac
from aegis_nexus.bench import load
from aegis_nexus.models import DAC

W = load()
T = W["epoch"] + 30
READ = ("repo", "read", "repo/project-x/src/main.py")


@pytest.fixture
def m():
    return DAC(W, seed=7)


@pytest.fixture
def s(m):
    return m.session("prod")


def check(m, chain, key=None, tool="repo", action="read", res="repo/project-x/src/main.py", now=T, proof="make"):
    if proof == "make":
        proof = dac.pop(key, chain, tool, action, res, int(now)) if key else None
    return m.verifiers[tool].check(chain, proof, action, res, now)


def resign(chain, i, key, **changes):
    """Replace hop i's link with a copy re-signed by `key` (the key that legitimately signs that hop)."""
    wit, link = chain[i]
    return [*chain[:i], (wit, dac.sign(key, "dac+jwt", {**dac.unverified(link), **changes})), *chain[i + 1:]]


def denied(reason, fn):
    with pytest.raises(dac.Denied, match=reason):
        fn()


def test_legit_chain_and_audit_path(m, s):
    assert check(m, s["linter"].token, s["linter"].key) == [
        "user:alice", "spiffe://aws.sim/agent/planner", "spiffe://gcp.sim/agent/coder", "spiffe://gcp.sim/tool-agent/linter"]


def test_capability_outside_task(m, s):
    denied("capability not granted", lambda: check(m, s["linter"].token, s["linter"].key, action="write"))


def test_widening_and_lifetime_extension(m, s):
    ln = s["linter"]
    wide = dac.delegate(ln.token, ln.key, ln.token[-1][0], ["repo:write:repo/*"], T, T + 60)
    denied("capability widening", lambda: check(m, wide, ln.key, action="write", res="repo/infra/terraform"))
    longer = dac.delegate(ln.token, ln.key, ln.token[-1][0], ["repo:read:repo/project-x/src/*"], T, T + 86400)
    denied("lifetime extension", lambda: check(m, longer, ln.key))


def test_every_link_must_be_live_even_without_the_exp_check(m, s):
    # the monotone-exp check is redundant with checking each hop's own exp: extension fails either way
    ln = s["linter"]
    longer = dac.delegate(ln.token, ln.key, ln.token[-1][0], ["repo:read:repo/project-x/src/*"], T, T + 86400)
    m.verifiers["repo"].attenuation = False
    denied("expired", lambda: check(m, longer, ln.key, now=W["epoch"] + 400))


def test_tampered_signature(m, s):
    chain = s["linter"].token
    wit, link = chain[-1]
    h, p, sig = link.split(".")
    bad = [*chain[:-1], (wit, f"{h}.{p}.{sig[:-4]}AAAA")]
    denied("Signature verification failed", lambda: check(m, bad, s["linter"].key))


def test_hop_signed_by_someone_other_than_the_parent_holder(m, s):
    denied("Signature", lambda: check(m, resign(s["linter"].token, 2, m.attacker), s["linter"].key))


def test_alg_none_and_hmac_confusion_rejected(m, s):
    chain = s["linter"].token
    claims = dac.unverified(chain[-1][1])
    none = jwt.encode(claims, None, algorithm="none", headers={"typ": "dac+jwt"})
    denied("dac\\+jwt", lambda: check(m, [*chain[:-1], (chain[-1][0], none)], s["linter"].key))
    x = dac.jwk(s["coder"].key.public_key())["x"].encode()
    hs = jwt.encode(claims, x, algorithm="HS256", headers={"typ": "dac+jwt"})
    denied("dac\\+jwt", lambda: check(m, [*chain[:-1], (chain[-1][0], hs)], s["linter"].key))


def test_wrong_typ(m, s):
    chain = s["linter"].token
    as_wit = [*chain[:-1], (chain[-1][0], dac.sign(s["coder"].key, "wit+jwt", dac.unverified(chain[-1][1])))]
    denied("wrong typ", lambda: check(m, as_wit, s["linter"].key))


def test_expired_link_and_wit_and_future_iat(m, s):
    denied("expired", lambda: check(m, s["linter"].token, s["linter"].key, now=W["epoch"] + 301))
    wit = dac.mint_wit(m.issuer("gcp.sim"), m.sid("linter"), s["linter"].key.public_key(), "prod", W["epoch"] - 7200, 3600)
    stale = dac.delegate(s["coder"].token, s["coder"].key, wit, ["repo:read:repo/project-x/src/*"], W["epoch"], W["epoch"] + 300)
    denied("expired", lambda: check(m, stale, s["linter"].key))
    future = resign(s["linter"].token, 2, s["coder"].key, iat=T + 600)
    denied("future", lambda: check(m, future, s["linter"].key))


def test_splice_child_under_another_parent(m, s):
    other = m.session("prod")  # same holder keys, different tokens
    spliced = [*other["coder"].token, s["linter"].token[-1]]
    denied("splice", lambda: check(m, spliced, s["linter"].key))


def test_depth_limit(m, s):
    ln = s["linter"]
    c = dac.delegate(ln.token, ln.key, ln.token[-1][0], ["repo:read:repo/project-x/src/*"], T, T + 60)
    assert check(m, c, ln.key)  # depth 3 == max
    c = dac.delegate(c, ln.key, ln.token[-1][0], ["repo:read:repo/project-x/src/*"], T, T + 60)
    denied("depth", lambda: check(m, c, ln.key))
    denied("depth", lambda: check(m, resign(s["linter"].token, 2, s["coder"].key, del_depth=1), ln.key))


def test_principal_env_policy_immutable(m, s):
    for k, v in (("obo", "user:bob"), ("env", "staging"), ("pv", "pv-0")):
        denied("changed mid-chain", lambda: check(m, resign(s["linter"].token, 2, s["coder"].key, **{k: v}), s["linter"].key))


def test_untrusted_trust_domain_and_cross_domain_issuer(m, s):
    evil = m.key("issuer/evil.sim")
    ln = s["linter"]
    wit = dac.mint_wit(evil, "spiffe://evil.sim/agent/x", ln.key.public_key(), "prod", T, 60)
    c = dac.delegate(s["coder"].token, s["coder"].key, wit, ["repo:read:repo/project-x/src/*"], T, T + 60)
    denied("untrusted trust domain", lambda: check(m, c, ln.key))
    # the azure issuer is trusted, but not for gcp.sim identities
    wit = dac.mint_wit(m.issuer("azure.sim"), m.sid("linter"), ln.key.public_key(), "prod", T, 60)
    c = dac.delegate(s["coder"].token, s["coder"].key, wit, ["repo:read:repo/project-x/src/*"], T, T + 60)
    denied("Signature", lambda: check(m, c, ln.key))


def test_untrusted_gateway(m):
    wit = dac.mint_wit(m.issuer("aws.sim"), m.sid("planner"), m.holder("planner", "prod").public_key(), "prod", T, 60)
    root = dac.mint_root("https://evil.sim", m.attacker, wit, "user:alice", ["*:*:*"], "pv-1", T, T + 60, 3)
    denied("untrusted gateway", lambda: check(m, root, m.holder("planner", "prod"), tool="storage", action="delete",
                                              res="bucket/backups/db.dump"))


def test_link_must_bind_its_workload_identity(m, s):
    ln = s["linter"]
    wit = dac.mint_wit(m.issuer("gcp.sim"), m.sid("linter"), m.attacker.public_key(), "prod", T, 60)
    swapped = [*ln.token[:-1], (wit, ln.token[-1][1])]  # attacker's own WIT under the linter's link
    denied("not bound", lambda: check(m, swapped, m.attacker))


def test_wrong_environment(m):
    st = m.session("staging")
    denied("wrong environment", lambda: check(m, st["linter"].token, st["linter"].key))


def test_revocation_cascades_to_descendants(m, s):
    m.revoke("coder", T - 1)
    denied("revoked", lambda: check(m, s["linter"].token, s["linter"].key))


def test_retired_policy_version(m, s):
    m.retire_pv(T - 1)
    denied("policy version", lambda: check(m, s["linter"].token, s["linter"].key))


def test_proof_of_possession(m, s):
    ln = s["linter"]
    denied("missing proof", lambda: check(m, ln.token))
    denied("Signature", lambda: check(m, ln.token, m.attacker))  # thief signs with own key
    other = dac.pop(ln.key, ln.token, "docs", *READ[1:], T)
    denied("another request", lambda: check(m, ln.token, proof=other))  # audience: made for another tool
    stale = dac.pop(ln.key, ln.token, *READ, T - 120)
    denied("stale proof", lambda: check(m, ln.token, proof=stale))
    wrong_tok = dac.pop(ln.key, s["coder"].token, *READ, T)
    denied("another token", lambda: check(m, ln.token, proof=wrong_tok))
    p = dac.pop(ln.key, ln.token, *READ, T)
    check(m, ln.token, proof=p)
    denied("replayed", lambda: check(m, ln.token, proof=p))


@pytest.mark.parametrize("chain", [None, [], "x", [("a", "b")], [(1, 2)], [("a",)]])
def test_malformed_input_fails_closed(m, chain):
    with pytest.raises(dac.Denied):
        m.verifiers["repo"].check(chain, None, "read", "x", T)


def test_wildcard_request_rejected(m, s):
    denied("capability not granted", lambda: check(m, s["linter"].token, s["linter"].key, res="repo/project-x/src/*"))


@pytest.mark.parametrize("parent,child,ok", [
    ("repo:read:repo/project-x/*", "repo:read:repo/project-x/src/a.py", True),
    ("repo:read:repo/project-x/*", "repo:read:repo/project-x-evil/a.py", False),
    ("repo:read:repo/project-x/*", "repo:*:repo/project-x/a.py", False),
    ("repo:*:repo/*", "repo:admin:repo/x", True),
    ("repo:read:repo/*", "*:read:repo/x", False),
    ("docs:read:docs/alice", "docs:read:docs/alice/x", False),
    ("*:*:*", "storage:delete:bucket/x", True),
])
def test_covers(parent, child, ok):
    assert dac.covers(parent, child) is ok
