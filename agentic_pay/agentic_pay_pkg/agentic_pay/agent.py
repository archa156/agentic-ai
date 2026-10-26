"""
agent.py — the AI agent sandbox (Layer 2): the constrained autonomous prover.

The architectural insight: the agent is the PROVER, not a router. It holds the
transaction amount it chose, so it is the only entity that can generate the
Bulletproof. It therefore cannot claim it spent within budget without producing
a cryptographic proof — even if the agent is compromised or adversarial.

Three internal components run in order; nothing reaches the network until all
pass:

  1. DecisionEngine  — picks (tx_amount, merchant, category) given user intent.
  2. IntentChecker   — pure-Python gate: verifies the decision ⊆ policy BEFORE
                       any proof is generated. If the agent tries to exceed its
                       mandate, execution stops here and nothing is published.
  3. ZKPProver       — calls bp_wrap.prove() ONLY if the intent check passed,
                       producing (proof, C_tx, r_tx) bound to the chosen amount.

Security consequence: the agent cannot selectively prove. It must prove the
*actual* amount it chose. Choose 6000 against a 5000 budget and the proof flow
refuses (and even a forged proof fails verification). Choose 4900 and it can
prove it — but C_tx then binds it to paying 4900. The ZKP + Pedersen pair
removes the agent's ability to lie about either the amount or compliance.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import rangeproof as rp
from .group import Commitment, Scalar, commit
from .policy import Policy, PolicyResult, TxMeta, check
from .rangeproof import RangeProof


# --------------------------------------------------------------------------- #
# Decision
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Decision:
    tx_amount: int
    merchant_id: str
    category: str
    fee: int = 0


class DecisionEngine:
    """
    Stand-in for the model's planning step. In a real system this is the LLM /
    policy network choosing what to buy. Here it's an injectable callable so
    tests can drive both in-policy and adversarial decisions deterministically.
    """

    def __init__(self, chooser):
        self._chooser = chooser

    def decide(self, policy: Policy, context: dict) -> Decision:
        return self._chooser(policy, context)


# --------------------------------------------------------------------------- #
# Intent checker — the first gate (pure Python, non-cryptographic)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class IntentVerdict:
    in_policy: bool
    reasons: list[str]


class IntentChecker:
    """
    Verifies decision ⊆ policy BEFORE proving. This is the agent's own
    self-restraint gate. It is intentionally redundant with the later cvc5
    check: a *correct* agent never publishes an out-of-policy attempt at all.
    A *compromised* agent that skips this gate is still caught downstream by
    cvc5 + the range proof — defense in depth.
    """

    def verify(self, policy: Policy, decision: Decision, nonce: str) -> IntentVerdict:
        reasons = []
        if decision.tx_amount < 0:
            reasons.append("amount_nonnegative")
        if decision.tx_amount > policy.max_amount:
            reasons.append("amount_within_limit")
        if decision.merchant_id not in policy.allowed_merchants:
            reasons.append("merchant_allowed")
        if decision.category not in policy.allowed_categories:
            reasons.append("category_allowed")
        if nonce in policy.seen_nonces:
            reasons.append("not_replay")
        return IntentVerdict(in_policy=not reasons, reasons=reasons)


# --------------------------------------------------------------------------- #
# ZKP prover
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProverOutput:
    proof: RangeProof
    C_tx: Commitment
    r_tx: Scalar          # kept by the agent for the balance step (not published)


class ZKPProver:
    """bp_wrap.prove(): commit to the chosen amount and prove it is in range."""

    def __init__(self, bits: int = rp.DEFAULT_BITS):
        self.bits = bits

    def prove(self, tx_amount: int) -> ProverOutput:
        C_tx, r_tx = commit(tx_amount)
        proof = rp.prove(tx_amount, r_tx, bits=self.bits)
        return ProverOutput(proof=proof, C_tx=C_tx, r_tx=r_tx)


# --------------------------------------------------------------------------- #
# Sandbox orchestration
# --------------------------------------------------------------------------- #
class OutOfPolicyAbort(Exception):
    """Raised when the intent checker stops execution before any proof."""

    def __init__(self, reasons: list[str]):
        super().__init__(f"agent aborted, out-of-policy: {reasons}")
        self.reasons = reasons


@dataclass(frozen=True)
class AgentArtifacts:
    """What an honest agent run emits toward the public channel."""

    decision: Decision
    prover_output: ProverOutput
    nonce: str
    agent_id: str


class AgentSandbox:
    def __init__(self, agent_id: str, engine: DecisionEngine,
                 checker: IntentChecker | None = None,
                 prover: ZKPProver | None = None,
                 enforce_intent_gate: bool = True):
        self.agent_id = agent_id
        self.engine = engine
        self.checker = checker or IntentChecker()
        self.prover = prover or ZKPProver()
        # If False we simulate a COMPROMISED agent that skips its own gate,
        # to demonstrate that downstream verification still catches it.
        self.enforce_intent_gate = enforce_intent_gate

    def run(self, policy: Policy, context: dict, nonce: str) -> AgentArtifacts:
        decision = self.engine.decide(policy, context)

        verdict = self.checker.verify(policy, decision, nonce)
        if self.enforce_intent_gate and not verdict.in_policy:
            # abort if out-of-policy — nothing reaches the network
            raise OutOfPolicyAbort(verdict.reasons)

        prover_output = self.prover.prove(decision.tx_amount)
        return AgentArtifacts(
            decision=decision,
            prover_output=prover_output,
            nonce=nonce,
            agent_id=self.agent_id,
        )
