import random
from typing import List, Tuple

from Crypto.Hash import SHA256
from Crypto.Util.number import isPrime
from sympy import n_order


def _hash_ints(ints: List[int]) -> int:
    hash_obj = SHA256.new()
    for x in ints:
        buf = x if isinstance(x, (bytes, bytearray)) else x.to_bytes((x.bit_length() + 7) // 8, "big")
        hash_obj.update(buf)
    return int.from_bytes(hash_obj.digest(), "big")


P_LENGTH = 16
Q_LENGTH = 2048 - P_LENGTH
SALT = b'\n'


def _gen_malicious_params(party_index: int) -> Tuple[int, int, int, int, Tuple[int, int], Tuple[int, int]]:
    """Search for suitable p, q, h1, h2."""

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 1
    mask_q = (0b11 << (Q_LENGTH - 2)) | 1

    p = q = 0
    while not isPrime(p):
        p = random.getrandbits(P_LENGTH) | mask_p
    while not isPrime(q):
        q = random.getrandbits(Q_LENGTH) | mask_q
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # search for h1, h2
    h1 = 1337
    while n_order(h1, p) != p - 1:
        h1 += 1
    h2 = pow(h1, p - 1, n)

    # build proof for log(h2, base=h1)
    g, v = h1, h2
    secret = p - 1
    r = 2**600  # just need something larger than e*secret
    x = pow(g, r, n)
    e = _hash_ints([SALT, party_index.to_bytes(8, 'big') + b'\x00', x, g, v, n])
    print(e)
    y = (r - e * secret) % phi_n
    proof_dlog_h2_base_h1 = (x, y)

    # forge proof for log(h1, base=h2)
    g, v = h2, h1
    r, x = 0, 1
    e = _hash_ints([SALT, party_index.to_bytes(8, 'big') + b'\x01', x, g, v, n])
    while e % (p - 1) != 0:
        r += 1
        x = x * g % n
        e = _hash_ints([SALT, party_index.to_bytes(8, 'big') + b'\x01', x, g, v, n])
    print(e)
    y = (r - e // (p - 1)) % phi_n
    proof_dlog_h1_base_h2 = (x, y)

    return p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2


if __name__ == '__main__':
    params = []
    for i in range(4):
        params.append(_gen_malicious_params(i))
    print(params)