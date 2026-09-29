"""CLI: run the DLS benchmark, or show one delegation chain being checked (demo)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import bench as B
from . import dac
from .models import DAC


def _write(base: Path, report: dict, md: str) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    base.with_suffix(".md").write_text(md, encoding="utf-8", newline="\n")
    print(f"wrote {base.with_suffix('.json')} and {base.with_suffix('.md')}")


def demo(world: dict, seed: int) -> int:
    m = DAC(world, seed)
    s, t = m.session(world["env"]), world["epoch"] + 30
    linter = s["linter"]
    print("linter chain:", " -> ".join(dac.unverified(link)["sub"] for _, link in linter.token))
    tries = [("legit read", linter, "repo", "read", "repo/project-x/src/main.py"),
             ("outside its task", linter, "repo", "write", "repo/project-x/main"),
             ("stolen chain, no key", B.Cred("thief", linter.token), "repo", "read", "repo/project-x/src/main.py")]
    tries += [(f"self-delegated {'widened' if i == 0 else 'widened + extended'}", c, "repo", "write", "repo/infra/terraform")
              for i, c in enumerate(m.delegate(linter, "repo:write:repo/infra/terraform", t))]
    for label, cred, tool, action, res in tries:
        try:
            print(f"ALLOW {label}: {m.verify(tool, action, res, m.request(cred, tool, action, res, t), t)}")
        except dac.Denied as e:
            print(f"DENY  {label}: {e}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis_nexus", description=__doc__)
    ap.add_argument("--world", default=str(B.WORLD))
    ap.add_argument("--seed", type=int, default=7)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench", help="run the DLS benchmark and write reports")
    b.add_argument("--out", default="reports")
    sub.add_parser("demo", help="mint a delegation chain and show which requests it allows")
    a = ap.parse_args(argv)
    world = B.load(Path(a.world))
    if a.cmd == "demo":
        return demo(world, a.seed)
    rep = B.bench(world, a.seed)
    rep["provenance"] = B.provenance(Path(a.world), seed=a.seed)
    for n, x in rep["summary"].items():
        print(f"{n:20s} DLS {x['dls_total']:>14,.2f}  zero-DLS {x['zero_dls_scenarios']:2d}  "
              f"legit {x['legit_allowed']}/{x['legit_calls']}")
    _write(Path(a.out) / "benchmark", rep, B.markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
