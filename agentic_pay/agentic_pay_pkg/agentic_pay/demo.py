"""
demo.py — end-to-end walkthrough of the full architecture.

Run:  python -m agentic_pay.demo
"""
from __future__ import annotations

from . import (
    AgentSandbox,
    Auditor,
    Decision,
    DecisionAggregator,
    DecisionEngine,
    ImmutableAuditLog,
    OutOfPolicyAbort,
    Policy,
    bank_commit,
    build_balance,
    merchant_commit,
    publish,
)


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def run_transaction(title, policy, decision, *, invoice, credit_limit, fee,
                    nonce, agent_id, log, enforce_gate=True):
    banner(title)
    print(f"Policy   : max_amount={policy.max_amount}  "
          f"merchants={sorted(policy.allowed_merchants)}  "
          f"categories={sorted(policy.allowed_categories)}")
    print(f"Agent    : id={agent_id}  enforce_intent_gate={enforce_gate}")
    print(f"Decision : amount={decision.tx_amount}  merchant={decision.merchant_id}  "
          f"category={decision.category}  fee={fee}")

    # ---- Layer 2: agent sandbox -----------------------------------------
    engine = DecisionEngine(lambda pol, ctx: decision)
    sandbox = AgentSandbox(agent_id, engine, enforce_intent_gate=enforce_gate)
    try:
        artifacts = sandbox.run(policy, context={}, nonce=nonce)
    except OutOfPolicyAbort as e:
        print(f"\n[Layer 2] Intent checker ABORTED before proving: {e.reasons}")
        print("          -> nothing published to the network. No proof generated.")
        return

    print("\n[Layer 2] Intent check passed -> bp_wrap.prove() generated a proof.")
    print(f"          C_tx = {artifacts.prover_output.C_tx.bytes().hex()[:24]}...")
    print(f"          range proof size ~ {artifacts.prover_output.proof.size_bytes()} bytes")

    # ---- Layer 3: other parties commit ----------------------------------
    merchant = merchant_commit(invoice)
    bank = bank_commit(credit_limit)
    balance = build_balance(decision.tx_amount, artifacts.prover_output.r_tx,
                            fee, bank)

    # ---- Layer 4: publish to shared public state ------------------------
    state = publish(artifacts, merchant, bank, balance)
    print(f"\n[Layer 4] Published. public_digest = {state.public_digest()[:24]}...")
    print("          (C_tx, C_inv, C_lim, C_fee published; no secret values exposed)")

    # ---- Layer 5 + 6: independent verification + aggregation ------------
    agg = DecisionAggregator().decide(state, policy, bank)
    r = agg.report
    print("\n[Layer 5] Independent checks:")
    print(f"          bp_wrap.verify (range) : {'PASS' if r.range_ok else 'FAIL'}")
    print(f"          Pedersen balance       : {'PASS' if r.balance_ok else 'FAIL'}")
    print(f"          cvc5 checkSat (policy) : {'PASS' if r.policy_ok else 'FAIL'}")
    if not r.policy_ok:
        print(f"            unsat-core (minimal) : {r.policy_violations}")
        print(f"            all violations       : {r.policy_all_violations}")
    print(f"\n[Layer 6] Aggregator: {'APPROVED' if agg.approved else 'REJECTED'}", end="")
    print(" -> agent executes payment." if agg.approved
          else f" -> failures: {r.failures()}")

    # ---- Layer 7: auditor reruns from public data only ------------------
    entry = Auditor(log).audit(state, policy, bank)
    print(f"\n[Layer 7] Auditor (no secrets) logged: decision={entry.decision}  "
          f"unsat-core={entry.unsat_core}")
    print(f"          audit entry hash = {entry.entry_hash[:24]}...  "
          f"agent_id={entry.agent_id}")


def main():
    policy = Policy.make(
        max_amount=5000,
        allowed_merchants=["amazon", "wholefoods"],
        allowed_categories=["groceries", "electronics"],
        seen_nonces=["nonce-replayed-001"],
    )
    log = ImmutableAuditLog()

    # 1) Compliant transaction -> APPROVED
    run_transaction(
        "SCENARIO 1 — compliant transaction (expect APPROVED)",
        policy,
        Decision(tx_amount=4900, merchant_id="wholefoods",
                 category="groceries", fee=100),
        invoice=4900, credit_limit=5000, fee=100,
        nonce="nonce-A-001", agent_id="agent-7f3a", log=log,
    )

    # 2) Over-budget decision, honest agent -> intent gate aborts pre-proof
    run_transaction(
        "SCENARIO 2 — over-budget, honest agent (expect ABORT before proving)",
        policy,
        Decision(tx_amount=6000, merchant_id="wholefoods",
                 category="groceries", fee=100),
        invoice=6000, credit_limit=5000, fee=100,
        nonce="nonce-B-002", agent_id="agent-7f3a", log=log,
    )

    # 3) COMPROMISED agent skips its own intent gate and tries to push an
    #    out-of-policy tx onto the channel -> cvc5 rejects, unsat-core names rule.
    run_transaction(
        "SCENARIO 3 — compromised agent skips gate (expect REJECTED downstream)",
        policy,
        Decision(tx_amount=6000, merchant_id="wholefoods",
                 category="groceries", fee=0),
        invoice=6000, credit_limit=6000, fee=0,
        nonce="nonce-C-003", agent_id="agent-EVIL", log=log,
        enforce_gate=False,
    )

    # 4) Disallowed category -> REJECTED, unsat-core = category_allowed
    run_transaction(
        "SCENARIO 4 — disallowed category (expect REJECTED: category_allowed)",
        policy,
        Decision(tx_amount=200, merchant_id="amazon",
                 category="gambling", fee=0),
        invoice=200, credit_limit=200, fee=0,
        nonce="nonce-D-004", agent_id="agent-7f3a", log=log,
        enforce_gate=False,
    )

    # 5) Replayed nonce -> REJECTED, unsat-core = not_replay
    run_transaction(
        "SCENARIO 5 — replayed nonce (expect REJECTED: not_replay)",
        policy,
        Decision(tx_amount=100, merchant_id="amazon",
                 category="electronics", fee=0),
        invoice=100, credit_limit=100, fee=0,
        nonce="nonce-replayed-001", agent_id="agent-7f3a", log=log,
        enforce_gate=False,
    )

    banner("IMMUTABLE AUDIT LOG")
    for i, e in enumerate(log.entries()):
        print(f"  #{i}  {e.decision:8}  agent={e.agent_id:11}  "
              f"core={e.unsat_core}  hash={e.entry_hash[:16]}...")
    print(f"\n  hash-chain integrity verified: {log.verify_chain()}")


if __name__ == "__main__":
    main()
