from typing import Optional, Tuple
from Crypto.Hash import SHA512
from sympy import primerange, isprime
import bisect
import random
import ecdsa

SMALL_PRIMES = list(primerange(10 ** 3, 10 ** 4))
SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def search_prime(nbits) -> int:
    """Find a prime `p` such that Zp* is of smooth order and p's 2 MSBs are 11."""
    min_p = 0b11 << (nbits - 2)
    max_p = (0b01 << nbits) - 1
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


def compute_x_x(x: int, l: Optional[int] = None) -> int:
    """Return x|$|x."""
    l = x.bit_length() if l is None else l
    l = (l + 7) // 8 * 8
    return x * (2 ** (l + 8) + 1) + ord('$') * 2 ** l


def hash_ints(ints) -> int:
    """Reimplement the buggy hash function of tss-lib."""
    hash_obj = SHA512.new(truncate="256")
    hash_obj.update(len(ints).to_bytes(8, "little"))
    for i in ints:
        hash_obj.update(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        hash_obj.update(b"$")
    return int.from_bytes(hash_obj.digest(), "big")


def eq_x_xi(q: int, set_x: set, x: int, xi: int) -> int:
    """
    return:
        - 1 if `x == xi`
        - 0 if `x != xi` and `x in `set_x`.
        - an element in Zq otherwise.
    """
    result = 1
    for xj in set_x:
        if xj == xi:
            continue
        result = result * (x - xj) % q
        result = result * pow(xi - xj, -1, q) % q
    return result


def secp256k1_scalar_base_mult(x: int) -> Tuple[int, int]:
    tmp = ecdsa.SigningKey.from_secret_exponent(x, ecdsa.SECP256k1).get_verifying_key().to_string()
    assert len(tmp) == 64
    return int.from_bytes(tmp[:32], "big"), int.from_bytes(tmp[32:], "big")
