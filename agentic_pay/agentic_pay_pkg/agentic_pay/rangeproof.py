"""
rangeproof.py — the bp_wrap.{prove,verify} range-proof primitive.

Goal (Layer 5 "bp_wrap.verify(): tx in [0, 2^64)"):
    Prove that the value committed in C_tx = v*G + r*H satisfies 0 <= v < 2^n
    WITHOUT revealing v.

Construction
------------
This is a non-interactive (Fiat-Shamir) bit-decomposition range proof:

  1. Write v in binary: v = sum_i b_i * 2^i ,  b_i in {0,1}.
  2. Commit to each bit:  C_i = b_i*G + s_i*H.
  3. For each C_i prove in zero knowledge that b_i in {0,1}
     using a Chaum-Pedersen style Sigma OR-proof:
         (C_i opens to 0)  OR  (C_i - G opens to 0)
     i.e. C_i is a commitment to 0 or to 1, and the prover knows the opening.
  4. Tie the bits to C_tx by choosing the per-bit blinders s_i so that
         sum_i 2^i * s_i  ==  r   (the blinding of C_tx).
     Then sum_i 2^i * C_i == v*G + r*H == C_tx, which the verifier checks
     directly (an exact point equality, no extra proof needed).

Security
--------
* Zero-knowledge: each bit commitment is perfectly hiding; each OR-proof is
  honest-verifier ZK (made non-interactive via Fiat-Shamir). The reconstruction
  check is a public linear combination of hiding commitments.
* Soundness: a cheating prover would need a bit commitment opening to something
  other than 0/1 (breaks the OR-proof => breaks discrete log) or a second
  opening of C_tx (breaks Pedersen binding => breaks discrete log).

Relationship to Bulletproofs
----------------------------
Bulletproofs prove the *same statement* (committed value in [0, 2^n)) with a
logarithmic-size proof via an inner-product argument. This module is the same
security goal with a simpler, linear-size proof (≈ a few hundred bytes per bit).
The public interface (`prove` / `verify` over a Pedersen `Commitment`) is
identical, so swapping in a Bulletproofs backend later changes nothing upstream.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .group import G, H, Commitment, Point, Scalar, commit_with

DEFAULT_BITS = 64  # tx in [0, 2^64), matching the diagram's n=64


# --------------------------------------------------------------------------- #
# Fiat-Shamir transcript
# --------------------------------------------------------------------------- #
def _challenge(*chunks: bytes) -> Scalar:
    h = hashlib.sha512()
    h.update(b"agentic-pay/rangeproof/fs/v1")
    for c in chunks:
        h.update(len(c).to_bytes(8, "little"))
        h.update(c)
    return Scalar.from_bytes_wide(h.digest())


# --------------------------------------------------------------------------- #
# Per-bit OR-proof:  C is a commitment to 0 OR to 1
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BitProof:
    C: bytes          # bit commitment encoding
    a0: bytes         # announcement for the "=0" branch
    a1: bytes         # announcement for the "=1" branch
    e0: int           # sub-challenge for branch 0
    e1: int           # sub-challenge for branch 1
    z0: int           # response for branch 0
    z1: int           # response for branch 1


def _prove_bit(bit: int, blind: Scalar) -> BitProof:
    """
    Prove C = bit*G + blind*H has bit in {0,1}.

    Branch 0 statement:  C       = blind*H           (knowledge of dlog wrt H)
    Branch 1 statement:  C - G   = blind*H

    Standard 2-of-2 Sigma OR: simulate the false branch, run the real branch,
    bind both with a single Fiat-Shamir challenge e = e0 + e1.
    """
    C = bit * G + blind * H if False else commit_with(bit, blind).point
    # P0 = C (commitment-to-0 target),  P1 = C - G (commitment-to-1 target)
    P0 = C
    P1 = C - G

    if bit == 0:
        # real branch = 0, simulate branch 1
        k = Scalar.random()
        a0 = H * k                      # real announcement
        e1 = Scalar.random()            # simulated challenge
        z1 = Scalar.random()            # simulated response
        a1 = H * z1 - P1 * e1           # back-solve announcement: a1 = z1*H - e1*P1
        e = _challenge(C.enc, a0.enc, a1.enc)
        e0 = e - e1
        z0 = k + e0 * blind
    elif bit == 1:
        # real branch = 1, simulate branch 0
        k = Scalar.random()
        a1 = H * k
        e0 = Scalar.random()
        z0 = Scalar.random()
        a0 = H * z0 - P0 * e0
        e = _challenge(C.enc, a0.enc, a1.enc)
        e1 = e - e0
        z1 = k + e1 * blind
    else:
        raise ValueError("bit must be 0 or 1")

    return BitProof(
        C=C.enc, a0=a0.enc, a1=a1.enc,
        e0=e0.value, e1=e1.value, z0=z0.value, z1=z1.value,
    )


def _verify_bit(bp: BitProof) -> bool:
    C = Point(bp.C)
    a0, a1 = Point(bp.a0), Point(bp.a1)
    e0, e1 = Scalar(bp.e0), Scalar(bp.e1)
    z0, z1 = Scalar(bp.z0), Scalar(bp.z1)

    P0 = C
    P1 = C - G

    # challenge must split correctly
    e = _challenge(bp.C, bp.a0, bp.a1)
    if (e0 + e1).value != e.value:
        return False
    # branch verification equations:  z*H == a + e*P
    if H * z0 != a0 + P0 * e0:
        return False
    if H * z1 != a1 + P1 * e1:
        return False
    return True


# --------------------------------------------------------------------------- #
# Range proof = n bit-proofs + linear reconstruction of C_tx
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RangeProof:
    bits: int
    bit_proofs: tuple[BitProof, ...]

    def size_bytes(self) -> int:
        # 32B C + 32B a0 + 32B a1 + 4*32B scalars per bit (approx wire size)
        return len(self.bit_proofs) * (32 * 3 + 32 * 4)


class RangeProofError(Exception):
    pass


def prove(value: int, blinding: Scalar, bits: int = DEFAULT_BITS) -> RangeProof:
    """
    bp_wrap.prove(): produce a proof that `value` (committed as value*G+blinding*H)
    lies in [0, 2^bits). The caller already holds C_tx = commit_with(value, blinding).
    """
    if value < 0 or value >= (1 << bits):
        # An honest prover must not be able to prove out-of-range values.
        raise RangeProofError(f"value {value} not in [0, 2^{bits})")

    # Choose per-bit blinders s_0..s_{n-2} freely, then fix the last so that
    #   sum_i 2^i * s_i == blinding   ==> reconstruction equals C_tx exactly.
    blinders: list[Scalar] = [Scalar.random() for _ in range(bits - 1)]
    acc = Scalar(0)
    for i in range(bits - 1):
        acc = acc + Scalar(1 << i) * blinders[i]
    # need s_{n-1} such that 2^{n-1} * s_{n-1} = blinding - acc
    inv = Scalar(pow(1 << (bits - 1), -1, _ORDER()))
    last = (blinding - acc) * inv
    blinders.append(last)

    bit_proofs = []
    for i in range(bits):
        b = (value >> i) & 1
        bit_proofs.append(_prove_bit(b, blinders[i]))

    return RangeProof(bits=bits, bit_proofs=tuple(bit_proofs))


def verify(proof: RangeProof, C_tx: Commitment) -> bool:
    """
    bp_wrap.verify(): check every bit is 0/1 and that the bit commitments
    reconstruct exactly to C_tx. Returns True iff the committed value is in range.
    Uses only public data (proof + C_tx) — no secrets.
    """
    if not all(_verify_bit(bp) for bp in proof.bit_proofs):
        return False
    # reconstruct sum_i 2^i * C_i and compare to C_tx
    acc = None
    for i, bp in enumerate(proof.bit_proofs):
        term = Point(bp.C) * Scalar(1 << i)
        acc = term if acc is None else acc + term
    return Commitment(acc) == C_tx


def _ORDER() -> int:
    from .group import L
    return L
