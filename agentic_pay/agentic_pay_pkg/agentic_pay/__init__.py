"""
agentic_pay — agentic AI payment verification.

AI agent as constrained prover · Pedersen commitments (rbcl/Ristretto255)
· zero-knowledge range proof (bp_wrap) · cvc5 SMT policy.
"""
from .agent import (
    AgentSandbox,
    Decision,
    DecisionEngine,
    IntentChecker,
    OutOfPolicyAbort,
    ZKPProver,
)
from .channel import (
    Auditor,
    DecisionAggregator,
    ImmutableAuditLog,
    SharedPublicState,
    publish,
    verify_all,
)
from .group import Commitment, Scalar, commit, commit_with
from .parties import bank_commit, build_balance, check_balance, merchant_commit
from .policy import Policy, PolicyResult, TxMeta, check
from . import rangeproof

__all__ = [
    "AgentSandbox", "Decision", "DecisionEngine", "IntentChecker",
    "OutOfPolicyAbort", "ZKPProver", "Auditor", "DecisionAggregator",
    "ImmutableAuditLog", "SharedPublicState", "publish", "verify_all",
    "Commitment", "Scalar", "commit", "commit_with", "bank_commit",
    "build_balance", "check_balance", "merchant_commit", "Policy",
    "PolicyResult", "TxMeta", "check", "rangeproof",
]
