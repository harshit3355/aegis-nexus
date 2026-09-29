# AEGIS NEXUS benchmark: Delegation Leakage Surface

_Synthetic, simulated deployment (three mock trust domains, one gateway, four agents, six tools). Every number below was produced by the command in the provenance section._

- 26 compromise scenarios (1 negative case: S26), 22 weighted authority targets, horizon 2160 h (the static key's lifetime).
- 30 legitimate cross-cloud tool calls run first under every model.
- **DLS** = sum over targets of weight x hours the attacker can get that target accepted after compromise (weight-hours; lower is better). **Reach** = weighted share of all targets usable at any time.

## Summary (25 scenarios, negative case excluded)

| Model | Total DLS | Median DLS | Scenarios with DLS 0 | Mean reach | Legit calls allowed | Audit path complete | Median cold verify (us) |
|---|---|---|---|---|---|---|---|
| Static API key (baseline) | 3,932,550.6 | 241,918.13 | 3 | 88.0% | 30/30 | 0/30 | 3.0 |
| Workload identity federation, broad roles (baseline) | 149,971.58 | 27.53 | 3 | 27.9% | 30/30 | 0/30 | 188.4 |
| RFC 8693 token exchange, no attenuation (baseline) | 242,782.01 | 49.17 | 3 | 41.4% | 30/30 | 30/30 | 208.5 |
| DAC without attenuation (ablation) | 311.68 | 0 | 17 | 14.3% | 30/30 | 30/30 | 954.9 |
| DAC without holder binding / bearer chain (ablation) | 91 | 0.47 | 5 | 7.1% | 30/30 | 30/30 | 780.1 |
| **DAC (mechanism)** | 7.06 | 0 | 17 | 1.6% | 30/30 | 30/30 | 973.5 |

Verify latency is wall-clock on the machine in the provenance section, signature cache cleared per call; it is environment-dependent. Audit completeness means the tool can recover the full user -> planner -> ... -> caller path from the credential alone (true by construction of each format).

## Per scenario (DLS, weight-hours)

| ID | Family | Scenario | static | WI | 8693 | DAC-noatt | DAC-bearer | DAC |
|---|---|---|---|---|---|---|---|---|
| S01 | stolen token | researcher token leaked from logs | 241,918.13 | 27.53 | 49.17 | 0 | 0.9 | 0 |
| S02 | stolen token | coder token leaked from logs | 241,918.13 | 40.32 | 49.17 | 0 | 1.87 | 0 |
| S03 | stolen token | linter token leaked from logs | 241,918.13 | 8.85 | 49.17 | 0 | 0.13 | 0 |
| S04 | stolen token | planner (root) token leaked from logs | 241,918.13 | 92.43 | 49.17 | 0 | 49.17 | 0 |
| S05 | stolen token | trace store leak: every sub-agent token | 241,918.13 | 64.9 | 49.17 | 0 | 2.77 | 0 |
| S06 | stolen token | agent config / env vars leaked | 241,918.13 | 0 | 0 | 0 | 0 | 0 |
| S07 | compromised tool | third-party search tool records every request | 239,758.15 | 26.55 | 48.18 | 0 | 0.75 | 0 |
| S08 | compromised tool | docs tool records every request | 151,198.83 | 3.93 | 32.45 | 0 | 0.3 | 0 |
| S09 | compromised tool | repo tool records every request | 159,838.77 | 2.95 | 30.48 | 0 | 0.47 | 0 |
| S10 | compromised tool | model gateway records every request | 235,437.82 | 71.07 | 46.06 | 0 | 26.95 | 0 |
| S11 | replay after revocation | researcher token stolen, task cancelled at 3 min | 241,918.13 | 27.53 | 1.67 | 0 | 0.2 | 0 |
| S12 | replay after revocation | linter token stolen, parent (coder) revoked at 2 min | 241,918.13 | 8.85 | 49.17 | 0 | 0.03 | 0 |
| S13 | replay after revocation | researcher token stolen, policy version retired at 5 min | 241,918.13 | 27.53 | 49.17 | 0 | 0.4 | 0 |
| S14 | compromised sub-agent | researcher workload compromised, detected after 4 h | 448 | 139.99 | 49.17 | 49.17 | 0.9 | 0.9 |
| S15 | compromised sub-agent | coder workload compromised, detected after 4 h | 448 | 204.99 | 49.17 | 49.17 | 1.87 | 1.87 |
| S16 | compromised sub-agent | linter workload compromised, detected after 4 h | 448 | 45 | 49.17 | 49.17 | 0.13 | 0.13 |
| S17 | compromised sub-agent | researcher workload compromised, never detected | 241,918.13 | 60,479.53 | 49.17 | 49.17 | 0.9 | 0.9 |
| S18 | confused deputy | prompt-injected researcher steered for 10 min (no exfiltration) | 18.67 | 4.67 | 8.33 | 8.33 | 0.9 | 0.9 |
| S19 | confused deputy | prompt-injected coder steered for 10 min (no exfiltration) | 18.67 | 6.83 | 8.33 | 8.33 | 1.33 | 1.33 |
| S20 | over-broad delegation | linter key + token exfiltrated; attacker widens scope and extends lifetime | 241,918.13 | 8.85 | 49.17 | 49.17 | 0.13 | 0.13 |
| S21 | over-broad delegation | researcher key + token exfiltrated; attacker widens scope and extends lifetime | 241,918.13 | 27.53 | 49.17 | 49.17 | 0.9 | 0.9 |
| S22 | wrong environment | staging planner + coder tokens replayed against prod tools | 241,918.13 | 92.43 | 49.17 | 0 | 0 | 0 |
| S23 | issuer compromise | gcp.sim trust-domain signing key stolen | 0 | 88,559.32 | 0 | 0 | 0 | 0 |
| S24 | issuer compromise | delegation gateway / authorization server signing key stolen | 0 | 0 | 241,918.13 | 0 | 0 | 0 |
| S25 | forgery | outsider self-signs tokens claiming to be the planner | 0 | 0 | 0 | 0 | 0 | 0 |
| S26 | negative case | root workload (planner) compromised while its credential is valid, detected after 4 h **(negative)** | 448 | 469.97 | 200 | 200 | 200 | 200 |

## By family (DLS, weight-hours)

| Family | static | WI | 8693 | DAC-noatt | DAC-bearer | DAC |
|---|---|---|---|---|---|---|
| stolen token | 1,451,508.78 | 234.03 | 245.85 | 0 | 54.84 | 0 |
| compromised tool | 786,233.57 | 104.5 | 157.17 | 0 | 28.47 | 0 |
| replay after revocation | 725,754.39 | 63.91 | 100.01 | 0 | 0.63 | 0 |
| compromised sub-agent | 243,262.13 | 60,869.51 | 196.68 | 196.68 | 3.8 | 3.8 |
| confused deputy | 37.34 | 11.5 | 16.66 | 16.66 | 2.23 | 2.23 |
| over-broad delegation | 483,836.26 | 36.38 | 98.34 | 98.34 | 1.03 | 1.03 |
| wrong environment | 241,918.13 | 92.43 | 49.17 | 0 | 0 | 0 |
| issuer compromise | 0 | 88,559.32 | 241,918.13 | 0 | 0 | 0 |
| forgery | 0 | 0 | 0 | 0 | 0 | 0 |
| negative case | 448 | 469.97 | 200 | 200 | 200 | 200 |

## Negative case: what DAC does not bound

S26 (root workload (planner) compromised while its credential is valid, detected after 4 h): static 448, WI 469.97, 8693 200, DAC-noatt 200, DAC-bearer 200, DAC 200. Under DAC the attacker can use 15 targets: everything the root was granted, for as long as the root can renew. Attenuation only narrows authority below the compromised hop.

## Modelling assumptions

| Model | Assumption |
|---|---|
| static | one org-wide key (scope *:*:*) in every agent's environment, shared across envs, 90-day rotation; rotated when a compromise is detected; no per-task revocation |
| WI | each workload calls tools with its own JWT-SVID (bearer, 1 h) and a broad per-workload role; no user context; SVIDs cannot be revoked, issuance stops on detection |
| 8693 | RFC 8693 token exchange per hop with nested `act`; scope copied (no attenuation); exp clamped to the subject token; bearer; revocation by current actor only (RFC 8693 s4.1) |
| DAC-noatt | DAC chain with holder binding, but every hop inherits the root's capabilities and expiry |
| DAC-bearer | DAC chain with attenuation, but no proof of possession: the chain is a bearer token (the Macaroons/Biscuit bearer model) |
| DAC | DAC: attenuation + holder-bound PoP + per-hop workload identity + env/policy-version binding |

## Provenance

- commit: `fda796bb80f9ce3eaffcac89045f286d09d3caee`
- command: `python -m aegis_nexus bench --out reports`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- pyjwt: `2.10.1`
- cryptography: `50.0.1`
- fixture_sha256: `0cd21896db993ef4`
- generated_at: `2026-09-29T09:22:37+00:00`
- seed: `7`
