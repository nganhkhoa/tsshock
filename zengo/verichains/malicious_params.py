import random
from dataclasses import dataclass
from typing import Tuple, List

from Crypto.Hash import SHA256
from Crypto.Util.number import isPrime
from sympy import n_order


@dataclass
class Params:
    p: int
    q: int
    h1: int
    h2: int
    dlog_proof_h2_base_h1: Tuple[int, int]
    dlog_proof_h1_base_h2: Tuple[int, int]


def save_params(list_params: List[Params]):
    with open('params', 'w') as f:
        f.write(repr(list_params))


def load_params() -> List[Params]:
    with open('params', 'r') as f:
        return eval(f.read())


def _hash_ints(ints: List[int]) -> int:
    hash_obj = SHA256.new()
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        hash_obj.update(buf)
    return int.from_bytes(hash_obj.digest(), "big")


P_LENGTH = 20
Q_LENGTH = 2048 - P_LENGTH


def _gen_malicious_params() -> Params:
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
    g, ni = h1, h2
    secret = p - 1
    r = 1337
    x = pow(g, r, N)
    e = _hash_ints([x, g, N, ni])
    y = (r - e * secret) % phiN
    proof_dlog_h2_base_h1 = (x, y)

    # forge proof for log(h1, base=h2)
    g, ni = h2, h1
    r, x = 0, 1
    e = _hash_ints([x, g, N, ni])
    while e % (p - 1) != 0:
        r += 1
        x = x * g % N
        e = _hash_ints([x, g, N, ni])
    y = (r - e // (p - 1)) % phiN
    proof_dlog_h1_base_h2 = (x, y)

    return Params(p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2)


if __name__ == '__main__':
    params = []
    for i in range(15):
        params.append(_gen_malicious_params())
        print("Finished:", i + 1)
    save_params(params)

