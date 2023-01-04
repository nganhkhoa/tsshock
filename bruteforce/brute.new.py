from typing import List, Tuple
from Crypto.Hash import SHA512
import random
from sympy import primerange, isprime, discrete_log, is_quad_residue, gcd
from sympy.ntheory.modular import crt
import bisect

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


def _hash_ints(ints: List[int]) -> int:
    hash_obj = SHA512.new(truncate='256')
    full_buf = b''
    for x in ints:
        buf = x.to_bytes((x.bit_length() + 7) // 8, "big")
        hash_obj.update(len(buf).to_bytes(2, "little"))
        hash_obj.update(buf)
        full_buf += len(buf).to_bytes(2, "little")
        full_buf += buf
    print(len(full_buf), list(full_buf)[128*4:])
    return int.from_bytes(hash_obj.digest(), "big")


N_LENGTH = 2048
P_LENGTH = 16
Q_LENGTH = N_LENGTH - P_LENGTH
SALT = int.from_bytes(b"ING TS dlog proof sub-protocol v1.0", "big")


def _gen_malicious_params() -> Tuple[int, int, int, int, Tuple[int, int], Tuple[int, int]]:
    """Search for suitable p, q, h1, h2."""

    # search for p, q
    mask_p = (0b11 << (P_LENGTH - 2)) | 0b11

    # p = q = 0
    # while not isprime(p):
    #     p = random.getrandbits(P_LENGTH) | mask_p
    # while not (isprime(q) and gcd(p - 1, q - 1) == 2 and is_quad_residue(2, q)):
    #     q = search_prime(2 ** (N_LENGTH - 1) // p + 1, 2 ** N_LENGTH // p - 1)
    # print("Done searching for p, q")
    p = 59399
    q = 272379560429502703646661135106056719719067080873162961823827215490061256422819659552373344951825546324458350620082031068529166308796854290135714817531606786573945775017894758654415070807593192678792937663299335046565532465330588833545771929405703217024587583716414780059599703421685510408057011889147073939499940948444788337443830285948044506503933809432637228751503995389916587635620395123173627949922582932614470156074759502701386357997787786757457957185361386462053568644592955219702419606232499979556498045137552432784518549944634447170594301216051839604055287716430710964545394442374937196964761786349154823
    N = p * q
    assert N.bit_length() == N_LENGTH
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
    #         print(err)
    #         h1 += 1
    #         continue
    #     break
    # print("Done searching for h1, h2")

    h1 = 3
    h2 = 13760615392898476588229320545557985480207268925712192831339750926557894674480849200585901386966226600311635873326544209582093481920417078737656312581696774857715740553904043207221049377199608094132619210749882406552490700148501347870732397873576126524082164729353274688610977016863551985815040240639710175423537016715430706807662306046095208468578736052536832796525981847098586007351542361622731684030088889755683032284896850076474038806048238986986775997004457244062946287924836097699366238506865898967194281240349148904273877143202932271058424097434938936796873135434079517928833327228781827190659765446359301657962

    assert pow(h1, order, N) == 1
    assert pow(h2, order, N) == 1
    print("h1", h1)
    print("h2", h2)

    # build proof for log(h2, base=h1)
    # g, V = h1, h2
    # assert pow(h1, secret, N) == h2
    # r = 1337
    # x = pow(g, r, N)
    # c = _hash_ints([SALT, N, g, V, x])
    # y = (r - c * secret) % order
    # proof_dlog_h2_base_h1 = (y, c)
    proof_dlog_h2_base_h1 = (None, None)

    # forge proof for log(h1, base=h2)
    # ATTENTION!
    # 1. check divisibility by (p-1)//2 instead of (p-1)
    # 2. use a resumable hash
    # 3. compute in Zp and Zq then combine
    g, V = h2, h1
    assert g % p == 1 and g % q == 2
    r, x, x_in_p, x_in_q = 0, 1, 1, 1

    inv_p_mod_q = pow(p, -1, q)
    while c % ((p - 1) // 2) != 0:
        r += 1

        x_in_q <<= 1
        if x_in_q > q:
            x_in_q -= q

        assert x_in_q == pow(2, r, q), "hmmge"

        x = ((x_in_q - 1) * inv_p_mod_q % q) * p + 1

        c = _hash_ints([SALT, N, g, V, x])
    y = (r - k_inv * c // ((p - 1) // 2)) % order
    proof_dlog_h1_base_h2 = (y, c)

    return p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2


if __name__ == '__main__':
    p, q, h1, h2, proof_dlog_h2_base_h1, proof_dlog_h1_base_h2 = _gen_malicious_params()
    print("RESULT:")
    print("p", p)
    print("q", q)
    print("h1", h1)
    print("h2", h2)
    # print("proof_dlog_h2_base_h1.y", hex(proof_dlog_h2_base_h1[0]).lstrip('0x'))
    # print("proof_dlog_h2_base_h1.c", hex(proof_dlog_h2_base_h1[1]).lstrip('0x'))
    print("proof_dlog_h1_base_h2.y", hex(proof_dlog_h1_base_h2[0]).lstrip('0x'))
    print("proof_dlog_h1_base_h2.c", hex(proof_dlog_h1_base_h2[1]).lstrip('0x'))

