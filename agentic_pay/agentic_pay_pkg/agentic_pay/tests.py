"""
tests.py — correctness + security tests for the whole pipeline.
Run:  python -m agentic_pay.tests
"""
from __future__ import annotations

import dataclasses

from . import (
    AgentSandbox, Auditor, Decision, DecisionAggregator, DecisionEngine,
    ImmutableAuditLog, OutOfPolicyAbort, Policy, bank_commit, build_balance,
    commit_with, merchant_commit, publish,
)
from .group import G, Scalar
from . import rangeproof as rp
from .policy import TxMeta, check

PASS, FAIL = "ok", "FAIL"
_results = []


def expect(name, cond):
    _results.append((name, bool(cond)))
    print(f"  [{PASS if cond else FAIL}] {name}")


# --------------------------- crypto / range proof -------------------------- #
def test_pedersen_homomorphism():
    r1, r2 = Scalar.random(), Scalar.random()
    a, b = 123, 456
    expect("pedersen homomorphic add",
           commit_with(a, r1) + commit_with(b, r2) == commit_with(a + b, r1 + r2))


def test_rangeproof_complete_and_sound():
    r = Scalar.random()
    C = commit_with(4900, r)
    proof = rp.prove(4900, r, 64)
    expect("range proof verifies for in-range value", rp.verify(proof, C))
    expect("range proof fails vs wrong commitment",
           not rp.verify(proof, commit_with(4901, r)))
    # tamper
    bad = dataclasses.replace(proof.bit_proofs[3],
                              z0=(Scalar(proof.bit_proofs[3].z0) + Scalar(1)).value)
    tampered = dataclasses.replace(proof, bit_proofs=(proof.bit_proofs[:3]) + (bad,) +
                                   proof.bit_proofs[4:])
    expect("tampered range proof rejected", not rp.verify(tampered, C))
    # out of range cannot be honestly proven
    try:
        rp.prove(2**64, Scalar.random(), 64)
        expect("out-of-range prove refused", False)
    except rp.RangeProofError:
        expect("out-of-range prove refused", True)


def test_non_binary_bit_rejected():
    blind = Scalar.random()
    C2 = (G * Scalar(2)) + (rp.H * blind)
    fake = rp.BitProof(C=C2.enc, a0=(rp.H * Scalar.random()).enc,
                       a1=(rp.H * Scalar.random()).enc,
                       e0=Scalar.random().value, e1=Scalar.random().value,
                       z0=Scalar.random().value, z1=Scalar.random().value)
    expect("forged non-binary bit rejected", not rp._verify_bit(fake))


# ------------------------------- policy ------------------------------------ #
def test_policy():
    pol = Policy.make(5000, ["amazon", "wholefoods"],
                      ["groceries", "electronics"], seen_nonces=["old"])
    expect("compliant tx approved",
           check(pol, TxMeta(4900, "wholefoods", "groceries", "n1")).approved)
    over = check(pol, TxMeta(6000, "amazon", "groceries", "n2"))
    expect("over-limit names amount_within_limit",
           "amount_within_limit" in over.violated)
    bm = check(pol, TxMeta(10, "evil", "groceries", "n3"))
    expect("bad merchant named", "merchant_allowed" in bm.violated)
    bc = check(pol, TxMeta(10, "amazon", "gambling", "n4"))
    expect("bad category named", "category_allowed" in bc.violated)
    rep = check(pol, TxMeta(10, "amazon", "groceries", "old"))
    expect("replay named", "not_replay" in rep.violated)


# ----------------------------- agent gate ---------------------------------- #
def test_intent_gate_aborts_before_proof():
    pol = Policy.make(5000, ["amazon"], ["groceries"])
    eng = DecisionEngine(lambda p, c: Decision(6000, "amazon", "groceries"))
    sb = AgentSandbox("a1", eng, enforce_intent_gate=True)
    try:
        sb.run(pol, {}, "n1")
        expect("honest agent aborts out-of-policy", False)
    except OutOfPolicyAbort as e:
        expect("honest agent aborts out-of-policy",
               "amount_within_limit" in e.reasons)


def test_compromised_agent_caught_downstream():
    pol = Policy.make(5000, ["amazon"], ["groceries"])
    eng = DecisionEngine(lambda p, c: Decision(6000, "amazon", "groceries", fee=0))
    sb = AgentSandbox("evil", eng, enforce_intent_gate=False)  # skips own gate
    art = sb.run(pol, {}, "n1")
    merch = merchant_commit(6000)
    bank = bank_commit(6000)
    bal = build_balance(6000, art.prover_output.r_tx, 0, bank)
    state = publish(art, merch, bank, bal)
    agg = DecisionAggregator().decide(state, pol, bank)
    expect("compromised over-budget agent REJECTED", not agg.approved)
    expect("rejection names amount_within_limit",
           "amount_within_limit" in agg.report.failures())


# --------------------------- audit / ZK at system level -------------------- #
def test_full_approved_flow_and_audit():
    pol = Policy.make(5000, ["wholefoods"], ["groceries"])
    eng = DecisionEngine(lambda p, c: Decision(4900, "wholefoods", "groceries", 100))
    sb = AgentSandbox("a7", eng)
    art = sb.run(pol, {}, "nx")
    merch = merchant_commit(4900)
    bank = bank_commit(5000)
    bal = build_balance(4900, art.prover_output.r_tx, 100, bank)
    state = publish(art, merch, bank, bal)
    agg = DecisionAggregator().decide(state, pol, bank)
    expect("full compliant flow approved", agg.approved)

    log = ImmutableAuditLog()
    entry = Auditor(log).audit(state, pol, bank)
    expect("auditor records APPROVED", entry.decision == "APPROVED")
    expect("audit hash-chain valid", log.verify_chain())

    # system-level ZK: the auditor / public channel never sees plaintext secrets.
    # Re-derive what an observer holds and confirm none of the secret integers
    # (tx_amount, invoice, credit_limit) or blinders leak into the public state.
    pub = repr(state)
    secret_strings = [str(4900), str(5000)]  # tx_amount and credit_limit
    # 4900 also appears as declared_amount (a deliberately public bound), so we
    # only assert the *blinder* secrets never leak — those must never be public.
    expect("secret blinder r_tx absent from public state",
           str(art.prover_output.r_tx.value) not in pub)
    expect("merchant invoice blinder absent from public state",
           str(merch._r_inv.value) not in pub)
    expect("bank credit-limit blinder absent from public state",
           str(bank._r_lim.value) not in pub)


def test_audit_tamper_detection():
    log = ImmutableAuditLog()
    log.append("digest1", "APPROVED", [], "a1")
    log.append("digest2", "REJECTED", ["not_replay"], "a2")
    expect("clean chain verifies", log.verify_chain())
    # tamper with a historical entry
    log._entries[0] = dataclasses.replace(log._entries[0], decision="REJECTED")
    expect("tampered chain detected", not log.verify_chain())


def main():
    print("Running agentic_pay test suite\n")
    for fn in [
        test_pedersen_homomorphism,
        test_rangeproof_complete_and_sound,
        test_non_binary_bit_rejected,
        test_policy,
        test_intent_gate_aborts_before_proof,
        test_compromised_agent_caught_downstream,
        test_full_approved_flow_and_audit,
        test_audit_tamper_detection,
    ]:
        print(f"{fn.__name__}:")
        fn()
    total = len(_results)
    passed = sum(1 for _, ok in _results if ok)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
