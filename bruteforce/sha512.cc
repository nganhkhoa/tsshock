#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool GET_IV = false;

//#region https://github.com/LeFroid/sha256-512
typedef struct PaddedMsg {
  size_t length;
  uint8_t msg[2048];
} PaddedMsg;

// Swaps the byte order of the 32 bit unsigned integer x
inline void endianSwap32(uint32_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(uint32_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

// Swaps the byte order of the 64 bit unsigned integer x
inline void endianSwap64(uint64_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(uint64_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

// Swaps the byte order of the 128 bit unsigned integer x
inline void endianSwap128(__uint128_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(__uint128_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

const int SHA512_MESSAGE_BLOCK_SIZE = 128;
// const int SHA512_HASH_SIZE = 64;
const int HASH_ARRAY_LEN = 8;
const int HASH_RESULT_ARRAY_LEN = 4;
// const unsigned long long MAX_VAL = 0xFFFFFFFFFFFFFFFFLLU;

// K: first 64 bits of the fractional parts of the cube roots of the first 80 primes
const static uint64_t K[80] =
{
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
 };

// Utility functions
// Rotate x to the right by numBits
#define ROTR(x, numBits) ( (x >> numBits) | (x << (64 - numBits)) )

// Compression functions
#define Ch(x,y,z) ( (x & y) ^ ((~x) & z) )
#define Maj(x,y,z) ( (x & y) ^ (x & z) ^ (y & z) )

#define BigSigma0(x) ( ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39) )
#define BigSigma1(x) ( ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41) )

#define SmallSigma0(x) ( ROTR(x,1) ^ ROTR(x,8) ^ (x >> 7) )
#define SmallSigma1(x) ( ROTR(x,19) ^ ROTR(x,61) ^ (x >> 6) )

// SHA512 message schedule
// Calculate the Nth block of W
void W(uint64_t* w, int N, uint64_t *M)
{
    uint64_t *mPtr = &M[(N * 16)];

    //printf("Message block %d : ", N);
    for (int i = 0; i < 16; ++i)
    {
        w[i] = *mPtr;
        ++mPtr;

    //printf("%" PRIx64 , w[i]);
    }
    //printf("\n");
    for (int i = 16; i < 80; ++i)
    {
        w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
    }
}

// Step 1:
// Preprocesses a given message of l bits.
// Appends "1" to end of msg, then k 0 bits such that l + 1 + k = 896 mod 1024
// and k is the smallest nonnegative solution to said equation. To this is appended
// the 128 bit block equal to the bit length l.
//char *preprocess(char *msg)
void preprocess(PaddedMsg& padded, const uint8_t *msg, size_t len, size_t original_len)
{
    // resulting msg wll be multiple of 1024 bits
    //size_t len = strlen(msg);
    if (msg == NULL || len == 0)
    {
        padded.length = 0;
        return;
    }

    size_t l = len * 8;
    size_t k = (896 - ( (original_len*8  + 1) % 1024 )) % 1024;
    // printf("k = %zu\n", k);
    // printf("l = %zu\n", l);
    // printf("l + k + 1 = %zu bits, %zu bytes\n", (l+k+1), ((l+k+1)/8));

    padded.length = ((l + k + 1) / 8) + 16;
    //printf("padded.length = %zu\n", padded.length);
    // padded.msg = (uint8_t*) malloc(sizeof(uint8_t) * padded.length);
    memset(&padded.msg[0], 0, sizeof(padded.msg));
    for (size_t i = 0; i < len; ++i)
        padded.msg[i] = msg[i];

    if (GET_IV) {
      padded.length = len;
      return;
    }
    // append to the binary string a 1 followed by k zeros
    padded.msg[len] = 0x80;

    // last 16 bytes reserved for length
    __uint128_t bigL = original_len*8;
    endianSwap128(&bigL);
    memcpy(&padded.msg[padded.length - sizeof(__uint128_t)], &bigL, sizeof(__uint128_t));
}

// Step 2:
// Parse the padded message into N 1024-bit blocks
// Each block separated into 64-bit words (therefore 16 per block)
// Returns an array of 8 64 bit words corresponding to the hashed value
uint64_t *getHash(uint64_t *retVal, PaddedMsg *p)
{
    size_t N = p->length / SHA512_MESSAGE_BLOCK_SIZE;
    //printf("Number of blocks = %zu\n", N);

    // vanila sha512
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

    // sha512/256
    uint64_t h[8] = {
        0x22312194FC2BF72C,
        0x9F555FA3C84C64C2,
        0x2393B86B6F53B151,
        0x963877195940EABD,
        0x96283EE2A88EFFE3,
        0xBE5E1E2553863992,
        0x2B0199FC2C85B8AA,
        0x0EB72DDC81C52CA2
    };

#if IS_LITTLE_ENDIAN
    // Convert byte order of message to big endian
    uint64_t *msg = ((uint64_t*)&p->msg[0]);
    for (int i = 0; i < N * 16; ++i)
        endianSwap64(msg++);
#endif

    uint64_t w[80];
    uint64_t reg[HASH_ARRAY_LEN];
    for (size_t i = 0; i < N; ++i)
    {
        uint64_t T1, T2;
        // initialize registers
        #pragma unroll
        for (int i2 = 0; i2 < HASH_ARRAY_LEN; ++i2)
            reg[i2] = h[i2];

        W(w, i, ((uint64_t*)(p->msg)));

        // Apply the SHA512 compression function to update registers
        #pragma unroll
        for (int j = 0; j < 80; ++j)
        {
            T1 = reg[7] + BigSigma1(reg[4]) + Ch(reg[4], reg[5], reg[6]) + K[j] + w[j];
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

        // printf("// start of round %llu\n", i + 1);
        // printf("uint64_t h[8] = {\n");
        // #pragma unroll
        // for (int i = 0; i < HASH_ARRAY_LEN; ++i)
        //     printf("    0x%016llx,\n", h[i]);
        // printf("};\n");
    }

    if (GET_IV) {
      // copy the whole h into hash array
      memcpy(retVal, h, sizeof(uint64_t) * 8);
      return retVal;
    }

    // Now the array h is the hash of the original message M
    memcpy(retVal, h, sizeof(uint64_t) * HASH_RESULT_ARRAY_LEN);
    #if IS_LITTLE_ENDIAN
        // Convert byte order of message to big endian
        uint64_t *retValPtr = retVal;
        #pragma unroll
        for (int i = 0; i < HASH_RESULT_ARRAY_LEN; ++i)
            endianSwap64(retValPtr++);
    #endif
    return retVal;
}

/// Wrapper for hashing methods, up to caller to free the return value
void SHA512Hash(uint64_t* result, const uint8_t *input, size_t len, size_t original_len)
{
    if (original_len == 0) {
      original_len = len;
    }
    struct PaddedMsg paddedMsg;
    preprocess(paddedMsg, input, len, original_len);
    getHash(result, &paddedMsg);
}
//#endregion

// export and use in python, bruh
extern "C"
#ifdef _WIN32
__declspec(dllexport)
#endif
void get_iv(uint8_t* content, size_t len, uint64_t* iv /* size 8 */) {
  GET_IV = true;
  SHA512Hash(iv, content, len - (len % 128), 0);
  GET_IV = false;
}
