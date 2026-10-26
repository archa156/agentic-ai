"""
policy.py — the cvc5 SMT policy layer (Layer 5 "cvc5 checkSat()").

The user's plaintext intent (Layer 1) is compiled into a set of *named* SMT
constraints. Given the public, non-secret transaction metadata
(merchant_id, category, nonce, declared amount bound) the solver decides
whether the transaction satisfies every policy rule.

Why an SMT solver and not an if-statement?
  * The constraints are declarative and audited as data, not code.
  * On violation, cvc5 returns an UNSAT CORE — the minimal set of named
    constraints that conflict. That names *exactly which rule the agent broke*,
    which is logged to the audit trail (Layer 7).
  * The same policy object is rerun verbatim by the independent auditor.

Constraints modelled here:
  amount_within_limit : tx_amount <= max_amount
  amount_nonnegative  : tx_amount >= 0
  merchant_allowed    : merchant_id in allowed_merchants
  category_allowed    : category in allowed_categories
  not_replay          : nonce not in seen_nonces   (replay protection)

`tx_amount` here is the *upper bound the agent publicly declares* and which the
Bulletproof independently proves the hidden amount respects. The SMT layer
checks policy logic; the ZKP layer checks the hidden value is really in range.
Together they remove the agent's ability to lie about amount or compliance.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import cvc5
from cvc5 import Kind


@dataclass(frozen=True)
class Policy:
    """Layer 1 user intent — plaintext, set once."""

    max_amount: int
    allowed_merchants: frozenset[str]
    allowed_categories: frozenset[str]
    # nonces already observed on-channel (replay protection state)
    seen_nonces: frozenset[str] = field(default_factory=frozenset)

    @staticmethod
    def make(max_amount, allowed_merchants, allowed_categories, seen_nonces=()):
        return Policy(
            max_amount=max_amount,
            allowed_merchants=frozenset(allowed_merchants),
            allowed_categories=frozenset(allowed_categories),
            seen_nonces=frozenset(seen_nonces),
        )


@dataclass(frozen=True)
class TxMeta:
    """Public transaction metadata that the SMT layer reasons about."""

    declared_amount: int   # public upper bound on the (hidden) tx amount
    merchant_id: str
    category: str
    nonce: str


@dataclass
class PolicyResult:
    sat: bool
    violated: list[str]        # minimal unsat-core rule names, [] if sat
    all_violations: list[str]  # every rule that fails (full audit view)

    @property
    def approved(self) -> bool:
        return self.sat


# Stable integer encoding for string-valued fields so we can use QF_LIA and
# keep unsat cores readable. (A real deployment could use the strings theory;
# integer interning keeps the solver fast and the cores crisp.)
def _intern(value: str, universe: list[str]) -> int:
    return universe.index(value) if value in universe else -1


def check(policy: Policy, meta: TxMeta) -> PolicyResult:
    """
    Run cvc5 checkSat() on the policy + this transaction's public metadata.
    Returns PolicyResult(sat, violated_constraint_names).
    """
    slv = cvc5.Solver()
    slv.setOption("produce-unsat-cores", "true")
    slv.setLogic("QF_LIA")
    Int = slv.getIntegerSort()

    # Build a deterministic universe for interning the allowed sets.
    merch_universe = sorted(policy.allowed_merchants | {meta.merchant_id})
    cat_universe = sorted(policy.allowed_categories | {meta.category})
    nonce_universe = sorted(policy.seen_nonces | {meta.nonce})

    amt = slv.mkConst(Int, "tx_amount")
    merch = slv.mkConst(Int, "merchant")
    cat = slv.mkConst(Int, "category")
    nonce = slv.mkConst(Int, "nonce")

    # Bind the symbolic vars to this transaction's concrete public values.
    facts = [
        slv.mkTerm(Kind.EQUAL, amt, slv.mkInteger(meta.declared_amount)),
        slv.mkTerm(Kind.EQUAL, merch, slv.mkInteger(_intern(meta.merchant_id, merch_universe))),
        slv.mkTerm(Kind.EQUAL, cat, slv.mkInteger(_intern(meta.category, cat_universe))),
        slv.mkTerm(Kind.EQUAL, nonce, slv.mkInteger(_intern(meta.nonce, nonce_universe))),
    ]
    for f in facts:
        slv.assertFormula(f)

    # Named policy constraints. We keep our own name->term map because we want
    # human-readable rule names in the audit log.
    named: dict[str, object] = {}

    named["amount_nonnegative"] = slv.mkTerm(Kind.GEQ, amt, slv.mkInteger(0))
    named["amount_within_limit"] = slv.mkTerm(Kind.LEQ, amt, slv.mkInteger(policy.max_amount))

    # merchant in allowed set  ==  OR over allowed ids
    allowed_merch_ids = [_intern(m, merch_universe) for m in policy.allowed_merchants]
    named["merchant_allowed"] = _in_set(slv, merch, allowed_merch_ids)

    allowed_cat_ids = [_intern(c, cat_universe) for c in policy.allowed_categories]
    named["category_allowed"] = _in_set(slv, cat, allowed_cat_ids)

    # not_replay: nonce must NOT equal any seen nonce
    seen_ids = [_intern(n, nonce_universe) for n in policy.seen_nonces]
    named["not_replay"] = _not_in_set(slv, nonce, seen_ids)

    # Assert constraints; track name by term-string so we can read the core back.
    term_to_name: dict[str, str] = {}
    for name, term in named.items():
        slv.assertFormula(term)
        term_to_name[str(term)] = name

    result = slv.checkSat()
    if result.isSat():
        return PolicyResult(sat=True, violated=[], all_violations=[])

    # UNSAT: pull the minimal core and map terms back to rule names.
    core = slv.getUnsatCore()
    violated = []
    for t in core:
        nm = term_to_name.get(str(t))
        if nm and nm not in violated:
            violated.append(nm)
    if not violated:
        violated = ["<policy-conflict>"]

    # Full audit view: evaluate each rule independently against the facts so the
    # log shows *every* rule the agent broke, not just the minimal witness.
    all_violations = _all_failing_rules(policy, meta)
    return PolicyResult(
        sat=False, violated=sorted(violated), all_violations=all_violations
    )


def _all_failing_rules(policy: "Policy", meta: "TxMeta") -> list[str]:
    fails = []
    if meta.declared_amount < 0:
        fails.append("amount_nonnegative")
    if meta.declared_amount > policy.max_amount:
        fails.append("amount_within_limit")
    if meta.merchant_id not in policy.allowed_merchants:
        fails.append("merchant_allowed")
    if meta.category not in policy.allowed_categories:
        fails.append("category_allowed")
    if meta.nonce in policy.seen_nonces:
        fails.append("not_replay")
    return fails


def _in_set(slv, var, ids: list[int]):
    if not ids:
        return slv.mkBoolean(False)
    eqs = [slv.mkTerm(Kind.EQUAL, var, slv.mkInteger(i)) for i in ids]
    return eqs[0] if len(eqs) == 1 else slv.mkTerm(Kind.OR, *eqs)


def _not_in_set(slv, var, ids: list[int]):
    if not ids:
        return slv.mkBoolean(True)
    neqs = [slv.mkTerm(Kind.NOT, slv.mkTerm(Kind.EQUAL, var, slv.mkInteger(i))) for i in ids]
    return neqs[0] if len(neqs) == 1 else slv.mkTerm(Kind.AND, *neqs)
