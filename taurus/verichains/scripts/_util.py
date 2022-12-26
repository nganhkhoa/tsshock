import bisect
import random
from typing import Tuple

import ecdsa
from sympy import primerange, isprime

SMALL_PRIMES = list(primerange(10 ** 3, 10 ** 4))
SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def search_prime(min_p, max_p) -> int:
    """Find a prime `p` such that Zp* is of smooth order."""
    lb = min_p // SMALL_PRIMES[-1] + 1
    ub = max_p // SMALL_PRIMES[0]
    while True:
        p = 2
        while p < lb:
            p *= random.choice(SMALL_PRIMES)
        if p > ub:
            continue
        p *= SMALL_PRIMES[bisect.bisect_right(SMALL_PRIMES, min_p // p)]
        p += 1
        if isprime(p):
            return p


def secp256k1_scalar_base_mult(x: int) -> Tuple[int, int]:
    tmp = ecdsa.SigningKey.from_secret_exponent(x, ecdsa.SECP256k1).get_verifying_key().to_string()
    assert len(tmp) == 64
    return int.from_bytes(tmp[:32], "big"), int.from_bytes(tmp[32:], "big")
