# agentic_pay — Agentic AI Payment Verification

A working prototype of the architecture in `agentic_bulletproofs_cvc5_full_architecture.png`:
an **AI agent acting as a constrained autonomous prover** for payments, where every
transaction is (a) proven within budget in zero knowledge, (b) checked against a
declarative SMT policy, and (c) auditable offline without revealing any secret.

The central idea: **the agent is the prover, not a router.** It holds the amount
it chose, so it is the only entity that can produce the range proof. It therefore
cannot claim it spent within budget without a cryptographic proof — even if it is
compromised or adversarial.

## What's real here

| Component | Library | Status |
|---|---|---|
| Pedersen commitments | `rbcl` (libsodium Ristretto255, prime-order group) | real |
| Zero-knowledge range proof (`bp_wrap`) | implemented from primitives | real, sound, ZK |
| SMT policy + unsat-core | `cvc5` | real |
| Multi-party balance | homomorphic point arithmetic | real |
| Hash-chained audit log | `hashlib` | real |

### One honest substitution: the range proof

The diagram specifies **Bulletproofs** (~608-byte logarithmic-size proof). There is
no reliable pip-installable Bulletproofs library, so `rangeproof.py` implements the
**same statement** (committed value ∈ [0, 2ⁿ)) with a **bit-decomposition + Sigma
OR-proof** construction instead:

* each bit is committed and proven ∈ {0,1} with a Chaum–Pedersen OR-proof,
* bit blinders are chosen so the bits reconstruct exactly to `C_tx`,
* made non-interactive with Fiat–Shamir.

This is genuinely zero-knowledge and sound. The only difference from Bulletproofs is
**proof size** (linear ≈ 14 KB at n=64, vs Bulletproofs' ~608 B). The public interface
(`prove(value, blinding)` / `verify(proof, C_tx)`) is identical, so a Bulletproofs
backend can be dropped in later with zero changes upstream.

## Architecture → code map

| Layer | Diagram | Module |
|---|---|---|
| 1 | User intent (plaintext policy) | `policy.Policy` |
| 2 | Agent sandbox: decision engine, intent checker, ZKP prover | `agent.py` |
| 3 | Multi-party Pedersen commitments | `group.py`, `parties.py` |
| 4 | Shared public state | `channel.SharedPublicState` |
| 5 | `bp_wrap.verify` · Pedersen balance · `cvc5 checkSat` | `rangeproof.py`, `parties.py`, `policy.py` |
| 6 | Decision aggregator (APPROVED iff all three pass) | `channel.DecisionAggregator` |
| 7 | Auditor + immutable audit log | `channel.Auditor`, `channel.ImmutableAuditLog` |

## Security properties demonstrated

* **Agent can't lie about the amount.** `C_tx` binds it; the range proof only verifies
  for the committed value. Choosing 6000 against a 5000 budget fails verification.
* **Honest agent self-aborts** before any proof is generated if out-of-policy
  (Layer 2 intent gate) — nothing reaches the network.
* **Compromised agent is still caught** downstream: skipping its own gate, an
  over-budget tx is rejected by `cvc5`, and the unsat-core names the broken rule.
* **Auditor learns nothing secret.** It reruns `verify()` + `cvc5` on public data only;
  `tx_amount`, invoice price, and credit limit stay hidden inside their commitments.
* **Tamper-evident audit log** via SHA-256 hash chain; each rejection records the
  violated constraint name and the `agent_id`.

## Run it

```bash
pip install rbcl cvc5
python -m agentic_pay.demo     # five end-to-end scenarios
python -m agentic_pay.tests    # 22 correctness + security checks
```

## Performance (n=64, single core)

prove ≈ 27 ms · verify ≈ 26 ms · cvc5 policy ≈ 4 ms · proof ≈ 14 KB.
(Bulletproofs would cut proof size to ~0.6 KB at higher prove cost.)

## Not production

This is a faithful architectural prototype, not audited crypto. Notably: the
balance step models bank↔payer blinder cooperation directly rather than over a real
private channel; nonce/replay state is in-memory; and the range proof is the
bit-decomposition variant rather than Bulletproofs.
