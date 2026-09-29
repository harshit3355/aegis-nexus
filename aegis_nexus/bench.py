"""Delegation Leakage Surface (DLS) benchmark.

DLS(scenario, model) = sum over authority targets of  weight x hours  during which an attacker holding the
scenario's loot can get a request for that target accepted, from the moment of compromise to the horizon.

Every attempt is a real request (signed token, PoP where the model has one) checked by the model's own tool
verifiers. Success only changes when some credential is issued, expires or is revoked, so time is integrated
exactly by evaluating once per interval between those change points (`tests/test_bench.py` checks that the
answer is constant inside each interval).
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.metadata as md
import json
import math
import platform
import random
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import jwt

from . import dac
from .dac import Denied
from .models import ASSUMPTIONS, Cred, Model, all_models

ROOT = Path(__file__).resolve().parent.parent
WORLD = ROOT / "fixtures" / "world.json"
REJECT = (Denied, jwt.PyJWTError, KeyError, IndexError, TypeError, ValueError)
BASELINES = ("static_api_key", "workload_identity", "rfc8693_exchange")


def load(path: Path = WORLD) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def split(cap: str) -> tuple[str, str, str]:
    t, a, r = cap.split(":", 2)
    return t, a, r


def legit_calls(world: dict, seed: int) -> list[tuple[int, str, str]]:
    """The benign workload: each call happens at a seeded random time inside its party's delegation lifetime."""
    rng, t0 = random.Random(seed), world["epoch"]
    calls = [(t0 + rng.randint(1, world["parties"][c["party"]]["ttl_s"] - 60), c["party"], c["cap"])
             for c in world["calls"] for _ in range(c["n"])]
    return sorted(calls)


def expected_path(world: dict, party: str) -> list[str]:
    path, p = [], party
    while p:
        path.append(world["parties"][p]["spiffe"])
        p = world["parties"][p]["parent"]
    return [world["user"], *reversed(path)]


def attempt(m: Model, tool: str, action: str, resource: str, req: dict, now: float) -> list[str] | None:
    try:
        return m.verify(tool, action, resource, req, now)
    except REJECT:
        return None


def run_legit(m: Model, world: dict, seed: int, sess: dict | None = None, timed: bool = False) -> tuple[dict, list]:
    """Run the benign workload. Returns summary and the request log (what each tool saw)."""
    sess, log, rows = sess or m.session(world["env"]), [], []
    for t, party, cap in legit_calls(world, seed):
        tool, action, resource = split(cap)
        req = m.request(sess[party], tool, action, resource, t)
        if timed:
            dac._verified.cache_clear()  # cold verification: every signature in the chain is checked
        t1 = time.perf_counter()
        audit = attempt(m, tool, action, resource, req, t)
        rows.append((audit is not None, audit == expected_path(world, party), time.perf_counter() - t1))
        log.append((t, tool, action, resource, req))
    return {"calls": len(rows), "allowed": sum(r[0] for r in rows), "audit_complete": sum(r[1] for r in rows),
            "median_verify_us": round(statistics.median(r[2] for r in rows) * 1e6, 1)}, log


class Attack:
    """One scenario against one model: what the attacker holds, and whether a target is usable at time t."""

    def __init__(self, m: Model, world: dict, sc: dict, seed: int):
        self.m, self.w, self.sc = m, world, sc
        t0 = world["epoch"]
        self.tc, self.end = t0 + world["compromise_at_s"], t0 + world["horizon_h"] * 3600
        self.sess = m.session(world["env"])
        _, log = run_legit(m, world, seed, self.sess)
        loot = m.session(sc["env"]) if sc.get("env") else self.sess
        self.held = [Cred(p, loot[p].token) for p in sc.get("steal", [])]
        self.held += [loot[p] for p in sc.get("exfil", [])]
        if sc.get("leak_config"):
            self.held += m.config_secrets()
        self.captured = [x for x in log if x[1] == sc.get("capture")]
        self.forge = ([f"issuer:{sc['issuer']}"] if sc.get("issuer") else []) + \
                     (["gateway"] if sc.get("gateway_key") else []) + (["outsider"] if sc.get("outsider") else [])
        self.party = sc.get("compromise") or sc.get("steer")
        span = sc.get("detect_after_s") if sc.get("compromise") else sc.get("steer_s")
        self.win_end = self.tc + span if span is not None else math.inf
        self._late = None
        if sc.get("compromise") and math.isfinite(self.win_end):
            m.detect(self.party, self.win_end)
        if sc.get("revoke"):
            m.revoke(sc["revoke"]["party"], t0 + sc["revoke"]["at_s"])
        if sc.get("retire_pv_at_s") is not None:
            m.retire_pv(t0 + sc["retire_pv_at_s"])

    def creds(self, t: float) -> list[Cred]:
        out = list(self.held)
        seen = set()
        for tc, *_, req in self.captured:
            if tc <= t and repr(req["token"]) not in seen:
                seen.add(repr(req["token"]))
                out.append(Cred("captured", req["token"]))
        if self.party:
            if t < self.win_end:
                out += [self.sess[self.party]] + [c for c in [self.m.refresh(self.party, t)] if c]
            elif self.sc.get("compromise"):  # exfiltrated before detection: last refresh just before it
                if self._late is None:
                    self._late = [c for c in [self.m.refresh(self.party, self.win_end - 1)] if c]
                out += [self.sess[self.party], *self._late]
        for kind in self.forge:
            out += self.m.forge(kind, t)
        return out

    def usable(self, cap: str, t: float) -> bool:
        tool, action, resource = split(cap)
        for cred in self.creds(t):
            for c in [cred, *self.m.delegate(cred, cap, t)]:
                if attempt(self.m, tool, action, resource, self.m.request(c, tool, action, resource, t), t) is not None:
                    return True
        return any(tc <= t and (tl, a, r) == (tool, action, resource) and attempt(self.m, tool, action, resource, req, t) is not None
                   for tc, tl, a, r, req in self.captured)

    def breakpoints(self) -> list[float]:
        t0, ttls = self.w["epoch"], [*self.w["ttl_s"].values(), *(p["ttl_s"] for p in self.w["parties"].values())]
        b = {self.tc, self.end, *(t0 + x for x in ttls)}
        if math.isfinite(self.win_end):
            b |= {self.win_end, *(self.win_end - 1 + x for x in ttls)}
        if self.sc.get("revoke"):
            b.add(t0 + self.sc["revoke"]["at_s"])
        if self.sc.get("retire_pv_at_s") is not None:
            b.add(t0 + self.sc["retire_pv_at_s"])
        for tc, *_ in self.captured:
            b |= {tc, tc + dac.POP_WINDOW}
        return sorted(x for x in b if self.tc <= x <= self.end)

    def targets(self) -> list[dict]:
        # a compromised tool already owns its own data; DLS counts authority usable elsewhere
        return [x for x in self.w["targets"] if split(x["cap"])[0] != self.sc.get("capture")]

    def measure(self) -> dict:
        secs = defaultdict(float)
        bps = self.breakpoints()
        for a, b in zip(bps, bps[1:]):
            for x in self.targets():
                if self.usable(x["cap"], (a + b) / 2):
                    secs[x["cap"]] += b - a
        weights = {x["cap"]: x["w"] for x in self.targets()}
        total_w = sum(weights.values())
        return {"dls": round(sum(weights[c] * s / 3600 for c, s in secs.items()), 2),
                "reach": round(sum(weights[c] for c in secs) / total_w, 4),
                "usable_targets": sorted(secs),
                "max_hours": round(max(secs.values(), default=0) / 3600, 3)}


def bench(world: dict, seed: int) -> dict:
    names = [m.name for m in all_models(world, seed)]
    legit = {}
    for m in all_models(world, seed):
        legit[m.name], _ = run_legit(m, world, seed, timed=True)
    rows = []
    for sc in world["scenarios"]:
        row = {k: sc.get(k) for k in ("id", "family", "title")} | {"negative": bool(sc.get("negative")), "models": {}}
        for m in all_models(world, seed):
            row["models"][m.name] = Attack(m, world, sc, seed).measure()
        rows.append(row)
    pos = [r for r in rows if not r["negative"]]
    summary = {n: {"dls_total": round(sum(r["models"][n]["dls"] for r in pos), 2),
                   "dls_median": statistics.median(r["models"][n]["dls"] for r in pos),
                   "zero_dls_scenarios": sum(r["models"][n]["dls"] == 0 for r in pos),
                   "mean_reach": round(statistics.mean(r["models"][n]["reach"] for r in pos), 4),
                   **{f"legit_{k}": v for k, v in legit[n].items()}} for n in names}
    families = defaultdict(lambda: defaultdict(float))
    for r in rows:
        for n in names:
            families[r["family"]][n] += r["models"][n]["dls"]
    return {"seed": seed, "fixture": world["version"], "synthetic": True, "scenarios": len(rows),
            "negative_cases": [r["id"] for r in rows if r["negative"]], "legit_calls": legit[names[0]]["calls"],
            "targets": len(world["targets"]), "horizon_h": world["horizon_h"], "models": names,
            "assumptions": ASSUMPTIONS, "summary": summary,
            "by_family": {f: {n: round(v, 2) for n, v in d.items()} for f, d in families.items()},
            "per_scenario": rows}


def provenance(world_path: Path, **extra) -> dict:
    def git(*args):
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    sha = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", "aegis_nexus", "fixtures"))
    return {"commit": (sha or "unknown") + ("-dirty" if dirty else ""),
            "command": "python -m aegis_nexus " + " ".join(sys.argv[1:]),
            "python": platform.python_version(), "platform": platform.platform(),
            "pyjwt": md.version("pyjwt"), "cryptography": md.version("cryptography"),
            "fixture_sha256": hashlib.sha256(world_path.read_bytes()).hexdigest()[:16],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            **extra}


LABELS = {"static_api_key": "Static API key (baseline)",
          "workload_identity": "Workload identity federation, broad roles (baseline)",
          "rfc8693_exchange": "RFC 8693 token exchange, no attenuation (baseline)",
          "dac_no_attenuation": "DAC without attenuation (ablation)",
          "dac_bearer": "DAC without holder binding / bearer chain (ablation)",
          "dac": "**DAC (mechanism)**"}
SHORT = {"static_api_key": "static", "workload_identity": "WI", "rfc8693_exchange": "8693",
         "dac_no_attenuation": "DAC-noatt", "dac_bearer": "DAC-bearer", "dac": "DAC"}


def _n(x: float) -> str:
    return f"{x:,.2f}".rstrip("0").rstrip(".") if x else "0"


def markdown(rep: dict) -> str:
    s, names = rep["summary"], rep["models"]
    neg = rep["negative_cases"]
    L = ["# AEGIS NEXUS benchmark: Delegation Leakage Surface", "",
         "_Synthetic, simulated deployment (three mock trust domains, one gateway, four agents, six tools). "
         "Every number below was produced by the command in the provenance section._", "",
         f"- {rep['scenarios']} compromise scenarios ({len(neg)} negative case: {', '.join(neg)}), "
         f"{rep['targets']} weighted authority targets, horizon {rep['horizon_h']} h (the static key's lifetime).",
         f"- {rep['legit_calls']} legitimate cross-cloud tool calls run first under every model.",
         "- **DLS** = sum over targets of weight x hours the attacker can get that target accepted after compromise "
         "(weight-hours; lower is better). **Reach** = weighted share of all targets usable at any time.", "",
         f"## Summary ({rep['scenarios'] - len(neg)} scenarios, negative case excluded)", "",
         "| Model | Total DLS | Median DLS | Scenarios with DLS 0 | Mean reach | Legit calls allowed | "
         "Audit path complete | Median cold verify (us) |", "|---|---|---|---|---|---|---|---|"]
    for n in names:
        x = s[n]
        L.append(f"| {LABELS[n]} | {_n(x['dls_total'])} | {_n(x['dls_median'])} | {x['zero_dls_scenarios']} | "
                 f"{100 * x['mean_reach']:.1f}% | {x['legit_allowed']}/{x['legit_calls']} | "
                 f"{x['legit_audit_complete']}/{x['legit_calls']} | {x['legit_median_verify_us']} |")
    L += ["", "Verify latency is wall-clock on the machine in the provenance section, signature cache cleared per "
              "call; it is environment-dependent. Audit completeness means the tool can recover the full "
              "user -> planner -> ... -> caller path from the credential alone (true by construction of each format).",
          "", "## Per scenario (DLS, weight-hours)", "",
          "| ID | Family | Scenario | " + " | ".join(SHORT[n] for n in names) + " |",
          "|---|---|---|" + "---|" * len(names)]
    for r in rep["per_scenario"]:
        tag = " **(negative)**" if r["negative"] else ""
        L.append(f"| {r['id']} | {r['family']} | {r['title']}{tag} | "
                 + " | ".join(_n(r["models"][n]["dls"]) for n in names) + " |")
    L += ["", "## By family (DLS, weight-hours)", "", "| Family | " + " | ".join(SHORT[n] for n in names) + " |",
          "|---|" + "---|" * len(names)]
    for f, d in rep["by_family"].items():
        L.append(f"| {f} | " + " | ".join(_n(d[n]) for n in names) + " |")
    L += ["", "## Negative case: what DAC does not bound", ""]
    for r in rep["per_scenario"]:
        if r["negative"]:
            L.append(f"{r['id']} ({r['title']}): " + ", ".join(f"{SHORT[n]} {_n(r['models'][n]['dls'])}" for n in names)
                     + f". Under DAC the attacker can use {len(r['models']['dac']['usable_targets'])} targets: "
                     "everything the root was granted, for as long as the root can renew. Attenuation only "
                     "narrows authority below the compromised hop.")
    L += ["", "## Modelling assumptions", "", "| Model | Assumption |", "|---|---|",
          *(f"| {SHORT[k]} | {v} |" for k, v in rep["assumptions"].items()), "",
          "## Provenance", "", *(f"- {k}: `{v}`" for k, v in rep["provenance"].items()), ""]
    return "\n".join(L)
