from typing import List, Tuple
from Crypto.Util.number import isPrime
from Crypto.Hash import SHA512
import random
from sympy import n_order


def _hash_ints(ints: List[int]) -> int:
    hash_obj = SHA512.new(truncate='256')
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        hash_obj.update(len(buf).to_bytes(2, "little"))
        hash_obj.update(buf)
    return int.from_bytes(hash_obj.digest(), "big")


P_LENGTH = 16
Q_LENGTH = 2048 - P_LENGTH
SALT = int.from_bytes(b"ING TS dlog proof sub-protocol v1.0", "big")


def _gen_malicious_params() -> Tuple[int, int, int, int, Tuple[int, int], Tuple[int, int]]:
    """Search for suitable p, q, h1, h2."""

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 1
    mask_q = (0b11 << (Q_LENGTH - 2)) | 1

    p = q = 0
    while not isPrime(p):
        p = random.getrandbits(P_LENGTH) | mask_p
    while not isPrime(q):
        q = random.getrandbits(Q_LENGTH) | mask_q
    N = p * q
    phiN = (p - 1) * (q - 1)

    # search for h1, h2
    h1 = 1337
    while n_order(h1, p) != p - 1:
        h1 += 1
    h2 = pow(h1, p - 1, N)

    # build proof for log(h2, base=h1)
    g, V = h1, h2
    secret = p - 1
    r = 1337
    x = pow(g, r, N)
    c = _hash_ints([SALT, N, g, V, x])
    y = (r - c * secret) % phiN
    proof_dlog_h2_base_h1 = (y, c)

    # forge proof for log(h1, base=h2)
    g, V = h2, h1
    r, x = 0, 1
    c = _hash_ints([SALT, N, g, V, x])
    while c % (p - 1) != 0:
        r += 1
        x = x * g % N
        c = _hash_ints([SALT, N, g, V, x])
    y = (r - c // (p - 1)) % phiN
    proof_dlog_h1_base_h2 = (y, c)

    return p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2
