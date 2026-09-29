import pytest

from aegis_nexus.bench import Attack, bench, load
from aegis_nexus.models import all_models

W = load()


@pytest.fixture(scope="module")
def rep():
    return bench(W, seed=7)


def row(rep, sid):
    return next(r for r in rep["per_scenario"] if r["id"] == sid)


def test_fixture_meets_the_contract():
    assert len(W["scenarios"]) >= 20 and sum(c["n"] for c in W["calls"]) == 30
    assert any(s.get("negative") for s in W["scenarios"])


def test_every_model_serves_the_legit_workload(rep):
    assert all(x["legit_allowed"] == x["legit_calls"] == 30 for x in rep["summary"].values())


def test_mechanism_bounds_a_compromised_sub_agent_to_its_task(rep):
    """Fails if attenuation or holder binding breaks: an exfiltrated linter key+token may only use the linter's
    task, and only until the linter's delegation expires."""
    task = {"repo:read:repo/project-x/src/main.py"}
    for sid in ("S16", "S20"):
        d = row(rep, sid)["models"]["dac"]
        assert set(d["usable_targets"]) <= task and d["max_hours"] <= W["parties"]["linter"]["ttl_s"] / 3600
    assert row(rep, "S01")["models"]["dac"]["dls"] == 0  # stolen chain without the key is useless
    assert row(rep, "S20")["models"]["dac_no_attenuation"]["dls"] > row(rep, "S20")["models"]["dac"]["dls"]
    assert row(rep, "S01")["models"]["dac_bearer"]["dls"] > 0


def test_dac_never_leaks_more_than_any_other_model(rep):
    for r in rep["per_scenario"]:
        assert all(r["models"]["dac"]["dls"] <= x["dls"] for x in r["models"].values()), r["id"]


def test_negative_case_is_not_bounded(rep):
    r = row(rep, "S26")["models"]
    assert r["dac"]["dls"] == r["rfc8693_exchange"]["dls"] > 0


@pytest.mark.parametrize("sid", ["S07", "S11", "S12", "S14", "S22", "S26"])
def test_success_is_constant_between_breakpoints(sid):
    """Justifies integrating by evaluating once per interval."""
    sc = next(s for s in W["scenarios"] if s["id"] == sid)
    for m in all_models(W, 7):
        if m.name in ("static_api_key", "dac_no_attenuation"):
            continue
        a = Attack(m, W, sc, 7)
        bps = a.breakpoints()
        for lo, hi in zip(bps, bps[1:]):
            if hi - lo < 4:
                continue
            probes = [lo + 1, (lo + hi) / 2, hi - 1]
            for x in a.targets():
                assert len({a.usable(x["cap"], t) for t in probes}) == 1, (sid, m.name, x["cap"], lo, hi)
