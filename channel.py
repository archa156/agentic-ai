"""
channel.py — public channel, decision aggregator, auditor, audit log.

Layer 4  SharedPublicState : everything published, no secret exposed.
Layer 5  three independent verifications (range proof / balance / cvc5).
Layer 6  DecisionAggregator : APPROVED iff all three pass.
Layer 7  Auditor + ImmutableAuditLog : reruns verification from public data only.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from . import rangeproof as rp
from .agent import AgentArtifacts
from .group import Commitment
from .parties import (
    BalanceWitness,
    BankCommitment,
    MerchantCommitment,
    check_balance,
)
from .policy import Policy, TxMeta, check


# --------------------------------------------------------------------------- #
# Layer 4 — shared public state (no secrets)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SharedPublicState:
    proof: rp.RangeProof
    C_tx: Commitment
    C_inv: Commitment
    C_lim: Commitment
    C_fee: Commitment
    merchant_id: str
    category: str
    declared_amount: int     # public upper bound the SMT policy reasons about
    nonce: str
    agent_id: str
    timestamp: float

    def public_digest(self) -> str:
        """Hash of the public fields — anchors the audit log entry."""
        h = hashlib.sha256()
        for part in (
            self.C_tx.bytes(), self.C_inv.bytes(), self.C_lim.bytes(),
            self.C_fee.bytes(),
            self.merchant_id.encode(), self.category.encode(),
            str(self.declared_amount).encode(), self.nonce.encode(),
            self.agent_id.encode(),
        ):
            h.update(len(part).to_bytes(4, "little"))
            h.update(part)
        return h.hexdigest()


def publish(
    artifacts: AgentArtifacts,
    merchant: MerchantCommitment,
    bank: BankCommitment,
    balance: BalanceWitness,
) -> SharedPublicState:
    d = artifacts.decision
    return SharedPublicState(
        proof=artifacts.prover_output.proof,
        C_tx=artifacts.prover_output.C_tx,
        C_inv=merchant.C_inv,
        C_lim=bank.C_lim,
        C_fee=balance.C_fee,
        merchant_id=d.merchant_id,
        category=d.category,
        declared_amount=d.tx_amount,   # public bound; hidden amount is in C_tx
        nonce=artifacts.nonce,
        agent_id=artifacts.agent_id,
        timestamp=time.time(),
    )


# --------------------------------------------------------------------------- #
# Layer 5 + 6 — three independent checks, aggregated
# --------------------------------------------------------------------------- #
@dataclass
class VerificationReport:
    range_ok: bool
    balance_ok: bool
    policy_ok: bool
    policy_violations: list[str]          # minimal unsat core
    policy_all_violations: list[str]      # full audit view

    @property
    def approved(self) -> bool:
        return self.range_ok and self.balance_ok and self.policy_ok

    def failures(self) -> list[str]:
        f = []
        if not self.range_ok:
            f.append("range_proof")
        if not self.balance_ok:
            f.append("pedersen_balance")
        if not self.policy_ok:
            f.extend(self.policy_all_violations or self.policy_violations)
        return f


def verify_all(state: SharedPublicState, policy: Policy,
               bank: BankCommitment) -> VerificationReport:
    """
    Each party runs this independently on the public channel.

    range  : bp_wrap.verify(proof, C_tx)        -> hidden tx in [0, 2^64)
    balance: C_tx + C_fee == C_lim              -> spend+fee nets vs credit limit
    policy : cvc5 checkSat on public metadata   -> merchant/category/limit/replay
    """
    range_ok = rp.verify(state.proof, state.C_tx)

    balance_ok = check_balance(state.C_tx, BalanceWitness(state.C_fee), bank)

    meta = TxMeta(
        declared_amount=state.declared_amount,
        merchant_id=state.merchant_id,
        category=state.category,
        nonce=state.nonce,
    )
    pol = check(policy, meta)

    return VerificationReport(
        range_ok=range_ok,
        balance_ok=balance_ok,
        policy_ok=pol.approved,
        policy_violations=pol.violated,
        policy_all_violations=pol.all_violations,
    )


@dataclass
class AggregatedDecision:
    approved: bool
    report: VerificationReport
    state: SharedPublicState


class DecisionAggregator:
    """Layer 6: APPROVED iff all three pass -> agent executes payment."""

    def decide(self, state: SharedPublicState, policy: Policy,
               bank: BankCommitment) -> AggregatedDecision:
        report = verify_all(state, policy, bank)
        return AggregatedDecision(
            approved=report.approved, report=report, state=state
        )


# --------------------------------------------------------------------------- #
# Layer 7 — auditor + immutable audit log
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AuditEntry:
    public_digest: str
    decision: str                 # "APPROVED" / "REJECTED"
    unsat_core: list[str]         # named violated constraints (empty if approved)
    agent_id: str
    timestamp: float
    prev_hash: str                # hash chain -> tamper-evident log
    entry_hash: str

    def to_json(self) -> str:
        return json.dumps({
            "public_digest": self.public_digest,
            "decision": self.decision,
            "unsat_core": self.unsat_core,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }, sort_keys=True)


class ImmutableAuditLog:
    """
    Append-only hash-chained log. Each entry commits to the previous entry's
    hash, so any tampering with history is detectable.
    """

    GENESIS = "0" * 64

    def __init__(self):
        self._entries: list[AuditEntry] = []

    def _tip(self) -> str:
        return self._entries[-1].entry_hash if self._entries else self.GENESIS

    def append(self, public_digest: str, decision: str,
               unsat_core: list[str], agent_id: str) -> AuditEntry:
        prev = self._tip()
        ts = time.time()
        body = json.dumps({
            "public_digest": public_digest, "decision": decision,
            "unsat_core": unsat_core, "agent_id": agent_id,
            "timestamp": ts, "prev_hash": prev,
        }, sort_keys=True).encode()
        entry_hash = hashlib.sha256(body).hexdigest()
        entry = AuditEntry(
            public_digest=public_digest, decision=decision, unsat_core=unsat_core,
            agent_id=agent_id, timestamp=ts, prev_hash=prev, entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for e in self._entries:
            body = json.dumps({
                "public_digest": e.public_digest, "decision": e.decision,
                "unsat_core": e.unsat_core, "agent_id": e.agent_id,
                "timestamp": e.timestamp, "prev_hash": e.prev_hash,
            }, sort_keys=True).encode()
            if e.prev_hash != prev:
                return False
            if hashlib.sha256(body).hexdigest() != e.entry_hash:
                return False
            prev = e.entry_hash
        return True


class Auditor:
    """
    Layer 7: offline, no secrets needed. Reruns bp_wrap.verify() on the public
    proof + C_tx and reruns cvc5 on the public policy fields. Learns the decision
    and any violated constraint names; learns NOTHING about tx_amount, invoice
    price, or credit limit (all stay hidden inside their commitments).
    """

    def __init__(self, log: ImmutableAuditLog):
        self.log = log

    def audit(self, state: SharedPublicState, policy: Policy,
              bank: BankCommitment) -> AuditEntry:
        # Independent re-verification from public data only.
        report = verify_all(state, policy, bank)
        decision = "APPROVED" if report.approved else "REJECTED"
        unsat_core = [] if report.approved else report.failures()
        return self.log.append(
            public_digest=state.public_digest(),
            decision=decision,
            unsat_core=unsat_core,
            agent_id=state.agent_id,
        )
