typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

namespace SHA512 {
//#region https://github.com/LeFroid/sha256-512
typedef struct PaddedMsg {
  size_t length;
  uint8_t msg[2048];
} PaddedMsg;

// Swaps the byte order of the 32 bit unsigned integer x
__device__ inline void endianSwap32(uint32_t *x) {
  char *y = (char *)x;
  for (size_t low = 0, high = sizeof(uint32_t) - 1; high > low; ++low, --high) {
    y[low] ^= y[high];
    y[high] ^= y[low];
    y[low] ^= y[high];
  }
}

// Swaps the byte order of the 64 bit unsigned integer x
__device__ inline void endianSwap64(uint64_t *x) {
  char *y = (char *)x;
  for (size_t low = 0, high = sizeof(uint64_t) - 1; high > low; ++low, --high) {
    y[low] ^= y[high];
    y[high] ^= y[low];
    y[low] ^= y[high];
  }
}

// Swaps the byte order of the 128 bit unsigned integer x
__device__ inline void endianSwap128(__uint128_t *x) {
  char *y = (char *)x;
  for (size_t low = 0, high = sizeof(__uint128_t) - 1; high > low;
       ++low, --high) {
    y[low] ^= y[high];
    y[high] ^= y[low];
    y[low] ^= y[high];
  }
}

#define SHA512_MESSAGE_BLOCK_SIZE 128
// const int SHA512_HASH_SIZE = 64;
#define HASH_ARRAY_LEN 8
#define HASH_RESULT_ARRAY_LEN 4
// const unsigned long long MAX_VAL = 0xFFFFFFFFFFFFFFFFLLU;

// K: first 64 bits of the fractional parts of the cube roots of the first 80
// primes
const static uint64_t K[80] = {
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
    0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
    0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
    0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
    0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
    0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
    0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817};

// Utility functions
// Rotate x to the right by numBits
#define ROTR(x, numBits) ((x >> numBits) | (x << (64 - numBits)))

// Compression functions
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define BigSigma0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define BigSigma1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define SmallSigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7))
#define SmallSigma1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6))

// SHA512 message schedule
// Calculate the Nth block of W
__device__ void W(uint64_t *w, int N, uint64_t *M) {
  uint64_t *mPtr = &M[(N * 16)];

  // printf("Message block %d : ", N);
  for (int i = 0; i < 16; ++i) {
    w[i] = *mPtr;
    ++mPtr;

    // printf("%" PRIx64 , w[i]);
  }
  // printf("\n");
  for (int i = 16; i < 80; ++i) {
    w[i] =
        SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
  }
}

// Step 1:
// Preprocesses a given message of l bits.
// Appends "1" to end of msg, then k 0 bits such that l + 1 + k = 896 mod 1024
// and k is the smallest nonnegative solution to said equation. To this is
// appended the 128 bit block equal to the bit length l.
// char *preprocess(char *msg)
__device__ void preprocess(PaddedMsg &padded, const uint8_t *msg, size_t len,
                           size_t original_len) {
  // resulting msg wll be multiple of 1024 bits
  // size_t len = strlen(msg);
  if (msg == NULL || len == 0) {
    padded.length = 0;
    return;
  }

  size_t l = len * 8;
  size_t k = (896 - ((original_len * 8 + 1) % 1024)) % 1024;
  // printf("k = %zu\n", k);
  // printf("l = %zu\n", l);
  // printf("l + k + 1 = %zu bits, %zu bytes\n", (l+k+1), ((l+k+1)/8));

  padded.length = ((l + k + 1) / 8) + 16;
  // printf("padded.length = %zu\n", padded.length);
  // padded.msg = (uint8_t*) malloc(sizeof(uint8_t) * padded.length);
  memset(&padded.msg[0], 0, sizeof(padded.msg));
  for (size_t i = 0; i < len; ++i)
    padded.msg[i] = msg[i];
  // append to the binary string a 1 followed by k zeros
  padded.msg[len] = 0x80;

  // last 16 bytes reserved for length
  __uint128_t bigL = original_len * 8;
  endianSwap128(&bigL);
  memcpy(&padded.msg[padded.length - sizeof(__uint128_t)], &bigL,
         sizeof(__uint128_t));

  // printf("l = %d\n", l);
  // printf("k = %d\n", k);
  // printf("padlen = %d\n", padded.length);
  // printf("bigl = %d\n", bigL);
}

// Step 2:
// Parse the padded message into N 1024-bit blocks
// Each block separated into 64-bit words (therefore 16 per block)
// Returns an array of 8 64 bit words corresponding to the hashed value
__device__ uint64_t *getHash(uint64_t *retVal, PaddedMsg *p) {
  size_t N = p->length / SHA512_MESSAGE_BLOCK_SIZE;
  // printf("Number of blocks = %zu\n", N);

  // initial hash value
  // uint64_t h[8] = {
  //     0x6A09E667F3BCC908,
  //     0xBB67AE8584CAA73B,
  //     0x3C6EF372FE94F82B,
  //     0xA54FF53A5F1D36F1,
  //     0x510E527FADE682D1,
  //     0x9B05688C2B3E6C1F,
  //     0x1F83D9ABFB41BD6B,
  //     0x5BE0CD19137E2179
  // };

  // uint64_t h[8] = {
  //     0x22312194FC2BF72C,
  //     0x9F555FA3C84C64C2,
  //     0x2393B86B6F53B151,
  //     0x963877195940EABD,
  //     0x96283EE2A88EFFE3,
  //     0xBE5E1E2553863992,
  //     0x2B0199FC2C85B8AA,
  //     0x0EB72DDC81C52CA2
  // };

  // start of round 4
  uint64_t h[8] = {
      0x3c4215ffb335eec9,
      0x3661b34283d95946,
      0xec547cf905e9143d,
      0x1de189b9f94abb5f,
      0x4131ecd40ef66b7d,
      0xc76285fcbadbeb82,
      0xffe30063f0a91944,
      0x19736f2d66f93554,
  };


#if MACHINE_BYTE_ORDER == LITTLE_ENDIAN
  // Convert byte order of message to big endian
  uint64_t *msg = ((uint64_t *)&p->msg[0]);
  for (int i = 0; i < N * 16; ++i)
    endianSwap64(msg++);
#endif

  uint64_t w[80];
  uint64_t reg[HASH_ARRAY_LEN];
  for (size_t i = 0; i < N; ++i) {
    uint64_t T1, T2;
// initialize registers
#pragma unroll
    for (int i2 = 0; i2 < HASH_ARRAY_LEN; ++i2)
      reg[i2] = h[i2];

    W(w, i, ((uint64_t *)(p->msg)));

// Apply the SHA512 compression function to update registers
#pragma unroll
    for (int j = 0; j < 80; ++j) {
      T1 =
          reg[7] + BigSigma1(reg[4]) + Ch(reg[4], reg[5], reg[6]) + K[j] + w[j];
      T2 = BigSigma0(reg[0]) + Maj(reg[0], reg[1], reg[2]);

      reg[7] = reg[6];
      reg[6] = reg[5];
      reg[5] = reg[4];
      reg[4] = reg[3] + T1;
      reg[3] = reg[2];
      reg[2] = reg[1];
      reg[1] = reg[0];
      reg[0] = T1 + T2;
    }

// Compute the ith intermediate hash values
#pragma unroll
    for (int i = 0; i < HASH_ARRAY_LEN; ++i)
      h[i] += reg[i];
  }
  // Now the array h is the hash of the original message M
  memcpy(retVal, h, sizeof(uint64_t) * HASH_RESULT_ARRAY_LEN);
#if MACHINE_BYTE_ORDER == LITTLE_ENDIAN
  // Convert byte order of message to big endian
  uint64_t *retValPtr = retVal;
#pragma unroll
  for (int i = 0; i < HASH_RESULT_ARRAY_LEN; ++i)
    endianSwap64(retValPtr++);
#endif
  return retVal;
}

/// Wrapper for hashing methods, up to caller to free the return value
__device__ void SHA512Hash(uint64_t *result, const uint8_t *input, size_t len,
                           size_t original_len) {
  if (original_len == 0) {
    original_len = len;
  }
  PaddedMsg paddedMsg;
  preprocess(paddedMsg, input, len, original_len);
  getHash(result, &paddedMsg);
}
//#endregion
}; // namespace SHA512

namespace BigNum {
// https://github.com/indy256/codelibrary/blob/master/cpp/numeric/bigint.cpp
const int base_bits = 30;
const int base = (1 << base_bits);

// template<typename T>
// struct divmod_result {
//     T q, r;
//     __device__ divmod_result(T q,T r):q(q),r(r){}
// };

template <int BITS> struct bigint_t {
  typedef bigint_t<BITS> bigint;
  int z[(BITS + base_bits - 1) / base_bits], zn;

  // sign == 1 <==> value >= 0
  // sign == -1 <==> value < 0
  int sign;

  __device__ bigint_t(long long v = 0) : zn(0) {
    memset(z, 0, sizeof(z));
    *this = v;
  }
  __device__ bigint_t(const uint8_t *buf, size_t len) { fromBuffer(buf, len); }

  __device__ bigint &operator=(long long v) {
    sign = v < 0 ? -1 : 1;
    v *= sign;
    zn = 0;
    for (; v > 0; v = v / base)
      z[zn++] = (int)(v % base);
    return *this;
  }

  __device__ bigint &operator+=(const bigint &other) {
    if (sign == other.sign) {
      for (int i = 0, carry = 0; i < other.zn || carry; ++i) {
        if (i == zn)
          z[zn++] = 0;
        z[i] += carry + (i < other.zn ? other.z[i] : 0);
        carry = z[i] >= base;
        if (carry)
          z[i] -= base;
      }
    } else if (other != 0 ) {
      *this -= -other;
    }
    return *this;
  }

  __device__ friend bigint operator+(bigint a, const bigint &b) {
    a += b;
    return a;
  }

  __device__ bigint &operator-=(const bigint &other) {
    if (sign == other.sign) {
      if ((sign == 1 && *this >= other) || (sign == -1 && *this <= other)) {
        for (int i = 0, carry = 0; i < other.zn || carry; ++i) {
          z[i] -= carry + (i < other.zn ? other.z[i] : 0);
          carry = z[i] < 0;
          if (carry)
            z[i] += base;
        }
        trim();
      } else {
        *this = other - *this;
        this->sign = -this->sign;
      }
    } else {
      *this += -other;
    }
    return *this;
  }

  __device__ friend bigint operator-(bigint a, const bigint &b) {
    a -= b;
    return a;
  }

  __device__ bigint &operator*=(int v) {
    if (v < 0)
      sign = -sign, v = -v;
    for (int i = 0, carry = 0; i < zn || carry; ++i) {
      if (i == zn)
        z[zn++] = 0;
      long long cur = (long long)z[i] * v + carry;
      carry = (int)(cur / base);
      z[i] = (int)(cur % base);
    }
    trim();
    return *this;
  }

  __device__ bigint operator*(int v) const { return bigint(*this) *= v; }

  // __device__ static divmod_result<bigint> divmod(const bigint &a1, const
  // bigint &b1) {
  //     int norm = base / (b1.z[b1.zn-1] + 1);
  //     bigint a = a1.abs() * norm;
  //     bigint b = b1.abs() * norm;
  //     bigint q, r;
  //     q.zn=a.zn;

  //     for (int i = (int)a.zn - 1; i >= 0; i--) {
  //         r *= base;
  //         r += a.z[i];
  //         int s1 = b.zn < r.zn ? r.z[b.zn] : 0;
  //         int s2 = b.zn - 1 < r.zn ? r.z[b.zn - 1] : 0;
  //         int d = (int)(((long long)s1 * base + s2) / b.z[b.zn-1]);
  //         r -= b * d;
  //         while (r < 0)
  //             r += b, --d;
  //         q.z[i] = d;
  //     }

  //     q.sign = a1.sign * b1.sign;
  //     r.sign = a1.sign;
  //     q.trim();
  //     r.trim();
  //     return divmod_result<bigint>(q, r / norm);
  // }

  // __device__ bigint operator/(const bigint &v) const { return divmod(*this,
  // v).q; }

  __device__ bool divisible(const unsigned long long x) const {
    __uint128_t a = 0;
    for (int i = zn - 1; i >= 0; i--) {
      a = ((a * base) + z[i]) % x;
    }
    return a == 0;
  }
  __device__ bigint operator%(const bigint &b1) const {
    int norm = base / (b1.z[b1.zn - 1] + 1);
    bigint a = abs() * norm;
    bigint b = b1.abs() * norm;
    bigint r;

    for (int i = (int)a.zn - 1; i >= 0; i--) {
      r *= base;
      r += a.z[i];
      int s1 = b.zn < r.zn ? r.z[b.zn] : 0;
      int s2 = b.zn - 1 < r.zn ? r.z[b.zn - 1] : 0;
      int d = (int)(((long long)s1 * base + s2) / b.z[b.zn - 1]);
      r -= b * d;
      while (r < 0)
        r += b, --d;
    }

    r.sign = sign;
    r.trim();
    return r / norm;
  }

  __device__ void mod(bigint &r, const bigint &b1,
                      /*tmp storage values:*/ bigint &a, bigint &b,
                      bigint &tmp3) const {
    int norm = base / (b1.z[b1.zn - 1] + 1);
    a = *this;
    a.sign = 1;
    a *= norm;
    b = b1;
    b.sign = 1;
    b *= norm;
    r = 0;

    for (int i = (int)a.zn - 1; i >= 0; i--) {
      r *= base;
      r += a.z[i];
      int s1 = b.zn < r.zn ? r.z[b.zn] : 0;
      int s2 = b.zn - 1 < r.zn ? r.z[b.zn - 1] : 0;
      int d = (int)(((long long)s1 * base + s2) / b.z[b.zn - 1]);
      tmp3 = b;
      tmp3 *= d;
      r -= tmp3;
      while (r < 0)
        r += b, --d;
    }

    r.sign = sign;
    r.trim();
    r /= norm;
  }

  __device__ bigint &operator/=(int v) {
    if (v < 0)
      sign = -sign, v = -v;
    for (int i = (int)zn - 1, rem = 0; i >= 0; --i) {
      long long cur = z[i] + rem * (long long)base;
      z[i] = (int)(cur / v);
      rem = (int)(cur % v);
    }
    trim();
    return *this;
  }

  __device__ bigint operator/(int v) const { return bigint(*this) /= v; }

  __device__ int operator%(int v) const {
    if (v < 0)
      v = -v;
    int m = 0;
    for (int i = (int)zn - 1; i >= 0; --i)
      m = (int)((z[i] + m * (long long)base) % v);
    return m * sign;
  }

  __device__ bigint &operator/=(const bigint &v) {
    *this = *this / v;
    return *this;
  }

  __device__ bigint &operator%=(const bigint &v) {
    *this = *this % v;
    return *this;
  }

  __device__ bool operator<(const bigint &v) const {
    if (sign != v.sign)
      return sign < v.sign;
    if (zn != v.zn)
      return zn * sign < v.zn * v.sign;
    for (int i = (int)zn - 1; i >= 0; i--)
      if (z[i] != v.z[i])
        return z[i] * sign < v.z[i] * sign;
    return false;
  }

  __device__ bool operator>(const bigint &v) const { return v < *this; }

  __device__ bool operator<=(const bigint &v) const { return !(v < *this); }

  __device__ bool operator>=(const bigint &v) const { return !(*this < v); }

  __device__ bool operator==(const bigint &v) const {
    return sign == v.sign && z == v.z;
  }

  __device__ bool operator!=(const bigint &v) const { return !(*this == v); }

  __device__ void trim() {
    while (zn > 0 && z[zn - 1] == 0)
      zn--;
    if (zn == 0)
      sign = 1;
  }

  __device__ bool isZero() const { return zn == 0; }

  __device__ friend bigint operator-(bigint v) {
    if (v.zn != 0)
      v.sign = -v.sign;
    return v;
  }

  __device__ bigint abs() const { return sign == 1 ? *this : -*this; }

  __device__ long long longValue() const {
    long long res = 0;
    for (int i = (int)zn - 1; i >= 0; i--)
      res = res * base + z[i];
    return res * sign;
  }

  __device__ unsigned long long ullValue() const {
    unsigned long long res = 0;
    for (int i = (int)zn - 1; i >= 0; i--)
      res = res * base + z[i];
    return res;
  }

  __device__ bigint &operator*=(const bigint &v) {
    bigint tmp = *this;
    tmp.mul_simple(*this, v);
    return *this;
  }

  __device__ bigint operator*(const bigint &v) const {
    bigint res;
    mul_simple(res, v);
    return res;
  }

  __device__ void mul_simple(bigint &res, const bigint &v) const {
    res.sign = sign * v.sign;
    res.zn = (zn + v.zn);
    memset(res.z, 0, sizeof(z));
    for (int i = 0; i < zn; ++i)
      if (z[i])
        for (int j = 0, carry = 0; j < v.zn || carry; ++j) {
          long long cur =
              res.z[i + j] + (long long)z[i] * (j < v.zn ? v.z[j] : 0) + carry;
          carry = (int)(cur / base);
          res.z[i + j] = (int)(cur % base);
        }
    res.trim();
  }

  __device__ void plus_one() {
    // quick add 1 to last bit if even
    if (z[0] & 1 == 0) {
      z[0] &= 1;
      return;
    }

    for (int i = 0; i < zn; ++i) {
      for (int b = 0; b < base_bits; b++) {
        if (z[i] & (1 << b)) {
        } else {
          z[i] = ((z[i] >> b) | 1) << b;
          return;
        }
      }

      // this part is all 1, full conversion to 0
      z[i] = 0;
    }
  }

  // __device__ inline bigint powmod(uint64_t n, const bigint &MOD) const {
  //     bigint res=1, mul=*this;
  //     while(n>0) {
  //         if(n&1) res=res*mul%MOD;
  //         mul=mul*mul%MOD;
  //         n/=2;
  //     }
  //     return res;
  // }

  __device__ void toBuffer(uint8_t *buf, size_t &len) const {
    uint8_t *ptr = buf;
    int pb = 0;
    *ptr = 0;
    for (int i = 0; i < zn; i++) {
      for (int j = 0; j < base_bits; j++) {
        *ptr |= ((z[i] >> j) & 1) << pb;
        if (++pb == 8) {
          pb = 0;
          *++ptr = 0;
        }
      }
    }
    while (ptr > buf && *ptr == 0)
      ptr--;
    ptr++;
    for (uint8_t *a = buf, *b = ptr - 1; a < b; a++, b--) {
      uint8_t x = *a;
      *a = *b;
      *b = x;
    }
    len = (size_t)(ptr - buf);
  }

  __device__ bigint &fromBuffer(const uint8_t *buf, size_t len) {
    memset(z, 0, sizeof(z));
    zn = (len * 8 + base_bits - 1) / base_bits;
    int zi = 0, zb = 0;
    for (int i = len - 1; i >= 0; i--) {
      for (int j = 0; j < 8; j++) {
        z[zi] |= ((buf[i] >> j) & 1) << zb;
        if (++zb == base_bits) {
          zb = 0;
          zi++;
        }
      }
    }
    return *this;
  }
};

}; // namespace BigNum

extern "C" __global__ void brute(uint64_t *output, uint8_t *houtput,
                                 size_t p_len, const uint8_t *p_buf,
                                 size_t q_len, const uint8_t *q_buf,
                                 size_t p_inv_len, const uint8_t *p_inv_buf,
                                 uint64_t base, uint64_t kernel_batch_size) {
  uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;

#define bits 6000
  BigNum::bigint_t<bits> p(p_buf, p_len);
  BigNum::bigint_t<bits> q(q_buf, q_len);
  BigNum::bigint_t<bits> p_inv(p_inv_buf, p_inv_len);

  uint64_t r_base = base + kernel_batch_size * idx;

  uint8_t hbuf[350] = {29,  134, 157, 123, 41,  115, 255, 43,  109, 227, 254,
                       239, 223, 212, 136, 52,  96,  123, 32,  11,  147, 219,
                       176, 175, 170, 1,   130, 140, 32,  12,  197, 151, 237,
                       127, 248, 21,  169, 136, 246, 149, 106, 1,   0,   3};

  uint64_t hash[HASH_RESULT_ARRAY_LEN];

  BigNum::bigint_t<bits> x_mod_q = 1; // = x_in_q = pow(2, r, q)

  BigNum::bigint_t<bits> tmp;
  BigNum::bigint_t<bits> tmp1;
  BigNum::bigint_t<bits> tmp2;
  BigNum::bigint_t<bits> tmp3;

  // calculate pow(2, r, q)
  {
    BigNum::bigint_t<bits> mul = 2;
    uint64_t n = r_base;
    while (n > 0) {
      if (n & 1) {
        // x_mod_q *= mul;
        tmp = x_mod_q;
        mul.mul_simple(x_mod_q, tmp);

        // x_mod_q %= N;
        tmp = x_mod_q;
        tmp.mod(x_mod_q, q, tmp1, tmp2, tmp3);
      }
      tmp = mul;
      tmp.mul_simple(mul, tmp);

      tmp = mul;
      tmp.mod(mul, q, tmp1, tmp2, tmp3);
      n /= 2;
    }
  }

  BigNum::bigint_t<bits> hashnum;
  uint64_t pnum = p.ullValue();
  uint64_t condition = (pnum - 1) / 2;

  const BigNum::bigint_t<bits> one = 1;
  const BigNum::bigint_t<bits> two = 2;
  size_t x_len = 0;

  BigNum::bigint_t<bits> x;

  for (int i = 0; i < kernel_batch_size; i++) {
    if (output[0] != 0) {
      return;
    }

    // x = ((x_in_q - 1) * inv_p_mod_q % q) * p + 1

    x = x_mod_q - one;
    tmp = x;
    p_inv.mul_simple(x, tmp);

    tmp = x;
    tmp.mod(x, q, tmp1, tmp2, tmp3);

    tmp = x;
    p.mul_simple(x, tmp);

    x.plus_one();

    uint64_t r = r_base + i;
    size_t new_len = 44;

    x.toBuffer(hbuf + new_len + 2, x_len);
    hbuf[new_len++] = x_len % 256;
    hbuf[new_len++] = x_len / 256;
    new_len += x_len;

    SHA512::SHA512Hash(hash, hbuf, new_len, new_len + 128 * 4);

    hashnum.fromBuffer((uint8_t *)hash, 32);
    if (hashnum.divisible(condition)) {
      printf("should return here %llu\n", r);
      output[0] = r;
      memcpy(houtput, hash, 32);
      return;
    }

    // x_in_q <<= 1
    // if x_in_q > q:
    //     x_in_q -= q

    tmp = x_mod_q;
    two.mul_simple(x_mod_q, tmp);
    if (x_mod_q > q) {
      tmp = x_mod_q;
      tmp.mod(x_mod_q, q, tmp1, tmp2, tmp3);
    }
  }
}
