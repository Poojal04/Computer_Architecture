#include <openssl/aes.h>
#include <stdint.h>
#include <string.h>

#define AES_MAXNR 14
#define BLOCK_SIZE 16

typedef struct {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY_Custom;

/* ------------------------------------------------------------------ */
/* 64-bit parallel GF(2^8) helpers (Processes 8 bytes at once)       */
/* ------------------------------------------------------------------ */

// Independently rotates two 32-bit columns inside a 64-bit register
static inline __attribute__((always_inline)) uint64_t ror32_in_64(uint64_t x, int shift)
{
    uint64_t r_mask = (shift == 8) ? 0x00FFFFFF00FFFFFFULL : 0x0000FFFF0000FFFFULL;
    uint64_t l_mask = (shift == 8) ? 0xFF000000FF000000ULL : 0xFFFF0000FFFF0000ULL;
    return ((x >> shift) & r_mask) | ((x << (32 - shift)) & l_mask);
}

// Multiplies 8 independent bytes in parallel
static inline __attribute__((always_inline)) uint64_t gmul_64(uint64_t a, uint64_t b)
{
    uint64_t p = 0;
#define GMUL_STEP_64 \
    p ^= a & ((b & 0x0101010101010101ULL) * 0xFFULL); \
    a  = ((a << 1) & 0xFEFEFEFEFEFEFEFEULL) ^ (((a & 0x8080808080808080ULL) >> 7) * 0x1BULL); \
    b >>= 1;

    GMUL_STEP_64 GMUL_STEP_64 GMUL_STEP_64 GMUL_STEP_64
    GMUL_STEP_64 GMUL_STEP_64 GMUL_STEP_64 GMUL_STEP_64
#undef GMUL_STEP_64
    return p;
}

/* Fermat inversion: a^254 in GF(2^8) — 8 bytes in parallel */
static inline __attribute__((always_inline)) uint64_t ginv_64(uint64_t a)
{
    uint64_t a2 = gmul_64(a, a);
    uint64_t a3 = gmul_64(a2, a);
    uint64_t a6 = gmul_64(a3, a3);
    uint64_t a12 = gmul_64(a6, a6);
    uint64_t a14 = gmul_64(a12, a2);
    uint64_t a28 = gmul_64(a14, a14);
    uint64_t a56 = gmul_64(a28, a28);
    uint64_t a112 = gmul_64(a56, a56);
    uint64_t a126 = gmul_64(a112, a14);
    uint64_t a252 = gmul_64(a126, a126);
    return gmul_64(a252, a2);
}

static inline __attribute__((always_inline)) uint64_t affine_64(uint64_t x)
{
    uint64_t r1 = ((x << 1) & 0xFEFEFEFEFEFEFEFEULL) | ((x >> 7) & 0x0101010101010101ULL);
    uint64_t r2 = ((x << 2) & 0xFCFCFCFCFCFCFCFCULL) | ((x >> 6) & 0x0303030303030303ULL);
    uint64_t r3 = ((x << 3) & 0xF8F8F8F8F8F8F8F8ULL) | ((x >> 5) & 0x0707070707070707ULL);
    uint64_t r4 = ((x << 4) & 0xF0F0F0F0F0F0F0F0ULL) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL);
    return x ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x6363636363636363ULL;
}

static inline __attribute__((always_inline)) uint64_t xtime_64(uint64_t x)
{
    return ((x << 1) & 0xFEFEFEFEFEFEFEFEULL) ^ (((x & 0x8080808080808080ULL) >> 7) * 0x1BULL);
}

/* MixColumns for two columns simultaneously inside a 64-bit integer */
static inline __attribute__((always_inline)) uint64_t mix_columns_64(uint64_t n)
{
    uint64_t u = n ^ ror32_in_64(n, 8);   
    uint64_t t = u ^ ror32_in_64(u, 16);  
    return n ^ t ^ xtime_64(u);
}

/* ------------------------------------------------------------------ */
/* Fused SubBytes + ShiftRows macro                                  */
/* */
/* d0 holds cols 0 & 1. d1 holds cols 2 & 3.                         */
/* ------------------------------------------------------------------ */
#define SUBBYTES_SHIFTROWS_64(d0, d1) \
do { \
    uint64_t _s01 = affine_64(ginv_64(d0)); \
    uint64_t _s23 = affine_64(ginv_64(d1)); \
    \
    uint32_t _s0 = (uint32_t)(_s01); \
    uint32_t _s1 = (uint32_t)(_s01 >> 32); \
    uint32_t _s2 = (uint32_t)(_s23); \
    uint32_t _s3 = (uint32_t)(_s23 >> 32); \
    \
    uint32_t _n0 = (_s0 & 0x000000FFu) | (_s1 & 0x0000FF00u) | (_s2 & 0x00FF0000u) | (_s3 & 0xFF000000u); \
    uint32_t _n1 = (_s1 & 0x000000FFu) | (_s2 & 0x0000FF00u) | (_s3 & 0x00FF0000u) | (_s0 & 0xFF000000u); \
    uint32_t _n2 = (_s2 & 0x000000FFu) | (_s3 & 0x0000FF00u) | (_s0 & 0x00FF0000u) | (_s1 & 0xFF000000u); \
    uint32_t _n3 = (_s3 & 0x000000FFu) | (_s0 & 0x0000FF00u) | (_s1 & 0x00FF0000u) | (_s2 & 0xFF000000u); \
    \
    (d0) = ((uint64_t)_n1 << 32) | _n0; \
    (d1) = ((uint64_t)_n3 << 32) | _n2; \
} while(0)

/* ------------------------------------------------------------------ */
/* One full middle round (64-bit unrolled)                           */
/* ------------------------------------------------------------------ */
#define FULL_ROUND_64(d0, d1, rk64) \
do { \
    SUBBYTES_SHIFTROWS_64(d0, d1); \
    (d0) = mix_columns_64(d0) ^ (rk64)[0]; \
    (d1) = mix_columns_64(d1) ^ (rk64)[1]; \
} while(0)

/* ------------------------------------------------------------------ */
/* Final round (64-bit unrolled)                                     */
/* ------------------------------------------------------------------ */
#define FINAL_ROUND_64(d0, d1, rk64) \
do { \
    SUBBYTES_SHIFTROWS_64(d0, d1); \
    (d0) ^= (rk64)[0]; \
    (d1) ^= (rk64)[1]; \
} while(0)

/* ------------------------------------------------------------------ */
/* AES-128 encryption — 64-bit fully unrolled                        */
/* ------------------------------------------------------------------ */
__attribute__((hot))
void AES_encrypt_custom(const unsigned char * __restrict__ plaintext, 
                        unsigned char * __restrict__ ciphertext, 
                        const AES_KEY_Custom * __restrict__ enc_key)
{
    // Cast 32-bit round keys to 64-bit array (1 uint64_t = 2 columns)
    const uint64_t * __restrict__ rk64 = (const uint64_t *)__builtin_assume_aligned(enc_key->rd_key, 4);

    uint64_t d0, d1;

    /* Load plaintext natively as 64-bit integers */
    memcpy(&d0, plaintext, 8);
    memcpy(&d1, plaintext + 8, 8);

    /* Round 0: AddRoundKey */
    d0 ^= rk64[0]; 
    d1 ^= rk64[1];

    /* Rounds 1-9: Notice the offset steps by 2 because 2 * 64-bit = 16 bytes */
    FULL_ROUND_64(d0, d1, rk64 + 2);
    FULL_ROUND_64(d0, d1, rk64 + 4);
    FULL_ROUND_64(d0, d1, rk64 + 6);
    FULL_ROUND_64(d0, d1, rk64 + 8);
    FULL_ROUND_64(d0, d1, rk64 + 10);
    FULL_ROUND_64(d0, d1, rk64 + 12);
    FULL_ROUND_64(d0, d1, rk64 + 14);
    FULL_ROUND_64(d0, d1, rk64 + 16);
    FULL_ROUND_64(d0, d1, rk64 + 18);

    /* Round 10: no MixColumns */
    FINAL_ROUND_64(d0, d1, rk64 + 20);

    /* Store ciphertext */
    memcpy(ciphertext, &d0, 8);
    memcpy(ciphertext + 8, &d1, 8);
}

/* ------------------------------------------------------------------ */
/* Wrapper                                                           */
/* ------------------------------------------------------------------ */
void AES_code(unsigned char plaintext[16],
              unsigned char ciphertext[16],
              AES_KEY *enc_key)
{
    AES_encrypt_custom(plaintext, ciphertext, (AES_KEY_Custom *)enc_key); //Your AES code where there is no secret dependent memory access
    // AES_encrypt(plaintext, ciphertext, enc_key); //OpenSSL AES where there is secret dependent memory access
}
