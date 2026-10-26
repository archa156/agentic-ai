"""
parties.py — multi-party Pedersen commitments and the balance check.

Layer 3: each party publishes a 32-byte Pedersen commitment hiding a private
value, exposing no secret on the public channel (Layer 4):

    Payer/agent : C_tx  = tx_amount * G + r_tx  * H   (from the range-proof flow)
    Merchant    : C_inv = invoice    * G + r_inv * H   (invoice price hidden)
    Bank/issuer : C_lim = credit_lim * G + r_lim * H   (credit limit hidden)

Layer 5: Pedersen balance check (homomorphic, no secrets revealed):

    C_tx + C_fee == C_lim    (the spend + fee must net against the credit limit)

The verifier never learns tx_amount, invoice, fee, or credit_lim — it only
confirms the committed values balance, using point arithmetic on commitments.
The parties cooperate to publish matching blinders for the balancing identity
(the standard Pedersen-balance technique: blinders on both sides cancel).
"""
from __future__ import annotations

from dataclasses import dataclass

from .group import Commitment, Scalar, commit, commit_with


@dataclass(frozen=True)
class MerchantCommitment:
    C_inv: Commitment
    _invoice: int          # private (held only by merchant)
    _r_inv: Scalar         # private blinder


@dataclass(frozen=True)
class BankCommitment:
    C_lim: Commitment
    _credit_limit: int     # private (held only by bank)
    _r_lim: Scalar         # private blinder


def merchant_commit(invoice: int) -> MerchantCommitment:
    C, r = commit(invoice)
    return MerchantCommitment(C_inv=C, _invoice=invoice, _r_inv=r)


def bank_commit(credit_limit: int) -> BankCommitment:
    C, r = commit(credit_limit)
    return BankCommitment(C_lim=C, _credit_limit=credit_limit, _r_lim=r)


@dataclass(frozen=True)
class BalanceWitness:
    """
    Public balancing artifact. The agent constructs C_fee so that the blinders
    on  C_tx + C_fee  match the blinder on  C_lim, making the balance identity a
    pure point equality the verifier can check without secrets.
    """

    C_fee: Commitment


def build_balance(
    tx_amount: int,
    r_tx: Scalar,
    fee: int,
    bank: BankCommitment,
) -> BalanceWitness:
    """
    Choose the fee blinder r_fee so that  r_tx + r_fee == r_lim.
    Then  C_tx + C_fee = (tx+fee)*G + r_lim*H,  and balance holds iff
    tx + fee == credit_limit (the value the bank committed).
    In a real protocol the bank reveals r_lim to the payer over a private
    channel; here we model that cooperation directly.
    """
    r_fee = bank._r_lim - r_tx
    C_fee = commit_with(fee, r_fee)
    return BalanceWitness(C_fee=C_fee)


def check_balance(
    C_tx: Commitment,
    balance: BalanceWitness,
    bank: BankCommitment,
) -> bool:
    """
    Layer 5 Pedersen balance:  C_tx + C_fee == C_lim  (point equality).
    Pure public-commitment arithmetic — no secret openings required.
    """
    return (C_tx + balance.C_fee) == bank.C_lim
