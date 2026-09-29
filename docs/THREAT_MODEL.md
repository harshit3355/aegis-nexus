# Threat model

AEGIS NEXUS v0.1 is a simulator: a delegation token format and verifier, three baseline credential
models, and a benchmark that attacks all of them in-process. Nothing here talks to a cloud, and none of it
is deployed. This document says what the verifier is meant to stop, what it cannot stop, and where the
benchmark's own trust assumptions sit.

## Assets

- Authority at the tools: the (tool, action, resource) targets in `fixtures/world.json`, each with a weight.
- The user's consent: the gateway grants hop 0 on behalf of `user:alice` for one session.
- Signing keys: one WIT issuer per trust domain (one per simulated cloud), the delegation gateway, and one
  holder key per workload.
- The audit path a tool reconstructs from a credential (user -> planner -> ... -> caller).

## Trust boundaries

| Component | Trust | Why |
|---|---|---|
| WIT issuers (`aws.sim`, `azure.sim`, `gcp.sim`) | trusted **for their own trust domain only** | stands in for SPIRE / cloud workload identity; a key for one domain cannot mint IDs in another |
| Delegation gateway | trusted for hop 0 | it decides the user's entitlement (the policy decision) and binds it to the root workload's WIT |
| Workloads (agents, tool-agents) | untrusted beyond their delegation | any of them may be compromised or prompt-injected |
| Tools | verify every request locally | one may be malicious and log everything it sees |
| Everything on the wire, in logs, in traces | untrusted | assume every token that crosses a boundary can be copied |

## Threats and controls (DAC)

| Threat | Control | Test |
|---|---|---|
| Stolen delegation chain replayed by someone else | leaf holder must sign a PoP over tool, action, resource, token hash, time and jti | `test_proof_of_possession` |
| Captured request (chain + PoP) replayed at the same tool | PoP jti replay cache, 60 s window | `test_proof_of_possession` |
| Captured request replayed at another tool | PoP names the tool (`htu`) | `test_proof_of_possession` |
| Sub-agent widens its scope or extends its lifetime when re-delegating | capability subset check; child `exp` <= parent `exp`; every hop's own `exp` is checked too | `test_widening_and_lifetime_extension`, `test_every_link_must_be_live_even_without_the_exp_check` |
| Hop signed by anyone but the parent's holder | hop i is verified with hop i-1's `cnf` key; `iss` must be that key's RFC 7638 thumbprint | `test_hop_signed_by_someone_other_than_the_parent_holder` |
| Child spliced under a different parent | `par_hash` = hash of the exact parent link | `test_splice_child_under_another_parent` |
| Unbounded chains | `del_depth` increments by one, bounded by the root's `del_max_depth` | `test_depth_limit` |
| Principal, environment or policy version switched mid-chain | must equal hop 0 on every hop | `test_principal_env_policy_immutable` |
| Link presented with someone else's workload identity | link `sub`, `cnf` and `wit_hash` must match the WIT at that hop | `test_link_must_bind_its_workload_identity` |
| Identity minted by an untrusted or wrong trust domain | WIT verified with the key of the domain in its SPIFFE ID; `iss` must be that domain | `test_untrusted_trust_domain_and_cross_domain_issuer` |
| Hop 0 minted by an untrusted gateway | gateway allow-list | `test_untrusted_gateway` |
| Staging credentials used in production | WIT and every link carry `env`; tools accept only their own | `test_wrong_environment` |
| Delegation must die before it expires (task cancelled, parent revoked) | revocation by workload and time; checked on every hop, so it cascades to descendants | `test_revocation_cascades_to_descendants` |
| Policy change must invalidate outstanding delegations | policy version retirement | `test_retired_policy_version` |
| `alg: none`, HMAC-with-public-key confusion, wrong token type | PyJWT with `algorithms=["EdDSA"]` only; `typ` checked per token kind | `test_alg_none_and_hmac_confusion_rejected`, `test_wrong_typ` |
| Malformed input crashes the verifier or is treated as allow | every parse or type error becomes `Denied` | `test_malformed_input_fails_closed` |

## What DAC does not stop

- **A compromised root workload** (the benchmark's negative case, S26). With the planner's key and a valid
  root delegation, the attacker can use everything the gateway granted the root, and keep renewing it until
  detection. Attenuation only narrows authority *below* the compromised hop. In the benchmark DAC leaks as
  much as RFC 8693 token exchange here.
- **A compromised holder within its own delegation.** A compromised sub-agent keeps its task's authority
  until the delegation expires or is revoked. DAC makes that window small; it does not make it zero.
- **A compromised gateway plus any compromised workload.** The gateway key alone is useless against DAC (it
  has no WIT whose key it holds, S24), but together with one workload key it can mint any root.
- **A compromised trust-domain issuer plus a delegation.** An issuer key alone mints identities that no
  delegation points at (S23); combined with a stolen parent key it is equivalent to that parent.
- **A tool that misuses what it is legitimately allowed.** DLS counts authority at *other* tools; a
  malicious tool already owns its own data.

## Benchmark trust assumptions

- The attacker's strategy is the one coded in `aegis_nexus/bench.py:Attack` (present every artifact held,
  with a fresh PoP when the key is held; re-delegate to itself with widened scope, with and without extended
  lifetime; replay every captured request; forge with every stolen signing key). A smarter attacker against
  a *baseline* would only raise the baseline's DLS; a smarter attacker against DAC is what the negative tests
  are for.
- Baseline modelling choices (shared static key, broad per-workload roles, no env binding in baseline tokens,
  RFC 8693 clamping `exp` to the subject token) are listed in the report and drive the baseline numbers.
- All keys are TEST ONLY, derived deterministically from a public seed (`dac.test_key`). Nothing in this
  repository is a real credential.

## Out of scope for v0.1

Real SPIRE / cloud workload identity, OPA/Cedar policy evaluation (the capability subset check is the
policy), durable or distributed revocation and replay state (both are in-memory per tool), key rotation,
transport security (mTLS), and side channels.
