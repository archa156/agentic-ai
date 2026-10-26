"""
group.py — Ristretto255 prime-order group + Pedersen commitments.

This is the cryptographic substrate for Layer 3 of the architecture
(multi-party Pedersen commitments). It wraps `rbcl` (libsodium Ristretto255
bindings) so the rest of the codebase works with clean Scalar / Point types.

Ristretto255 is a prime-order group (order L below) built on Curve25519,
so there are no cofactor pitfalls — every encoded point is a valid group
element and Pedersen commitments are perfectly hiding / computationally binding.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import rbcl

# Order of the Ristretto255 group (prime).
L = 2**252 + 27742317777372353535851937790883648493


# --------------------------------------------------------------------------- #
# Scalars
# --------------------------------------------------------------------------- #
def _scalar_bytes(x: int) -> bytes:
    """Encode an int as a 32-byte little-endian canonical scalar mod L."""
    return (x % L).to_bytes(32, "little")


@dataclass(frozen=True)
class Scalar:
    """An integer mod L. Immutable; supports +, -, * in the scalar field."""

    value: int

    def __post_init__(self):
        object.__setattr__(self, "value", self.value % L)

    @staticmethod
    def random() -> "Scalar":
        return Scalar(secrets.randbelow(L))

    @staticmethod
    def from_bytes_wide(b: bytes) -> "Scalar":
        """Reduce arbitrary-length (>=64B) hash output into a scalar."""
        return Scalar(int.from_bytes(hashlib.sha512(b).digest(), "little") % L)

    def bytes(self) -> bytes:
        return _scalar_bytes(self.value)

    def __add__(self, o: "Scalar") -> "Scalar":
        return Scalar(self.value + o.value)

    def __sub__(self, o: "Scalar") -> "Scalar":
        return Scalar(self.value - o.value)

    def __mul__(self, o: "Scalar") -> "Scalar":
        return Scalar(self.value * o.value)

    def __neg__(self) -> "Scalar":
        return Scalar(-self.value)


# --------------------------------------------------------------------------- #
# Points
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Point:
    """A Ristretto255 group element (32-byte canonical encoding)."""

    enc: bytes  # 32 bytes

    def __add__(self, o: "Point") -> "Point":
        return Point(rbcl.crypto_core_ristretto255_add(self.enc, o.enc))

    def __sub__(self, o: "Point") -> "Point":
        return Point(rbcl.crypto_core_ristretto255_sub(self.enc, o.enc))

    def __mul__(self, s: Scalar) -> "Point":
        # scalar * point ; allow zero scalar -> identity
        return Point(
            rbcl.crypto_scalarmult_ristretto255_allow_scalar_zero(s.bytes(), self.enc)
        )

    __rmul__ = __mul__

    def is_valid(self) -> bool:
        return bool(rbcl.crypto_core_ristretto255_is_valid_point(self.enc))

    def __eq__(self, o) -> bool:
        return isinstance(o, Point) and self.enc == o.enc

    def __hash__(self):
        return hash(self.enc)


def basepoint() -> Point:
    """The canonical Ristretto255 generator G."""
    return Point(rbcl.crypto_scalarmult_ristretto255_base(_scalar_bytes(1)))


def hash_to_point(domain: bytes) -> Point:
    """Deterministic nothing-up-my-sleeve point from a domain string."""
    h = hashlib.sha512(domain).digest()  # 64 bytes
    return Point(rbcl.crypto_core_ristretto255_from_hash(h))


# Two independent generators with unknown relative discrete log.
# G is the standard basepoint; H is hash-to-point of a fixed domain string,
# so nobody knows x such that H = x*G  ->  Pedersen binding holds.
G = basepoint()
H = hash_to_point(b"agentic-pay/pedersen/H/v1")


# --------------------------------------------------------------------------- #
# Pedersen commitments:  C = v*G + r*H
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Commitment:
    """A Pedersen commitment point C = v*G + r*H (32 bytes on the wire)."""

    point: Point

    def bytes(self) -> bytes:
        return self.point.enc

    def __add__(self, o: "Commitment") -> "Commitment":
        return Commitment(self.point + o.point)

    def __sub__(self, o: "Commitment") -> "Commitment":
        return Commitment(self.point - o.point)

    def __eq__(self, o) -> bool:
        return isinstance(o, Commitment) and self.point == o.point

    def __hash__(self):
        return hash(self.point)


def commit(value: int, blinding: Scalar | None = None) -> tuple[Commitment, Scalar]:
    """Return (C, r) where C = value*G + r*H and r is fresh if not given."""
    r = blinding if blinding is not None else Scalar.random()
    C = Commitment(G * Scalar(value) + H * r)
    return C, r


def commit_with(value: int, blinding: Scalar) -> Commitment:
    return Commitment(G * Scalar(value) + H * blinding)
