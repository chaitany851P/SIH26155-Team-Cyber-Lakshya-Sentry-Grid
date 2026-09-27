#define SENTRY_EXPORTS
#include "sentry_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define Sigma1(x) (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define sigma0(x) (ROTR((x), 1) ^ ROTR((x), 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR((x), 19) ^ ROTR((x), 61) ^ ((x) >> 6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_process_block(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];
    int t;

    for (t = 0; t < 16; t++) {
        W[t] = ((uint64_t)block[t * 8 + 0] << 56) |
               ((uint64_t)block[t * 8 + 1] << 48) |
               ((uint64_t)block[t * 8 + 2] << 40) |
               ((uint64_t)block[t * 8 + 3] << 32) |
               ((uint64_t)block[t * 8 + 4] << 24) |
               ((uint64_t)block[t * 8 + 5] << 16) |
               ((uint64_t)block[t * 8 + 6] << 8)  |
               ((uint64_t)block[t * 8 + 7]);
    }
    for (t = 16; t < 80; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (t = 0; t < 80; t++) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K512[t] + W[t];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sentry_sha512(const uint8_t *data, size_t len, uint8_t digest[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    size_t full_blocks = len / 128;
    size_t i;
    for (i = 0; i < full_blocks; i++) {
        sha512_process_block(state, data + i * 128);
    }

    size_t rem = len % 128;
    uint8_t tail[256];
    memset(tail, 0, sizeof(tail));
    if (rem > 0) {
        memcpy(tail, data + full_blocks * 128, rem);
    }
    tail[rem] = 0x80;

    size_t total_pad = (rem < 112) ? 128 : 256;
    uint64_t bit_len = (uint64_t)len * 8;
    /* Big-endian 128-bit length at end of last block */
    tail[total_pad - 8] = (uint8_t)(bit_len >> 56);
    tail[total_pad - 7] = (uint8_t)(bit_len >> 48);
    tail[total_pad - 6] = (uint8_t)(bit_len >> 40);
    tail[total_pad - 5] = (uint8_t)(bit_len >> 32);
    tail[total_pad - 4] = (uint8_t)(bit_len >> 24);
    tail[total_pad - 3] = (uint8_t)(bit_len >> 16);
    tail[total_pad - 2] = (uint8_t)(bit_len >> 8);
    tail[total_pad - 1] = (uint8_t)(bit_len);

    sha512_process_block(state, tail);
    if (total_pad == 256) {
        sha512_process_block(state, tail + 128);
    }

    for (i = 0; i < 8; i++) {
        digest[i * 8 + 0] = (uint8_t)(state[i] >> 56);
        digest[i * 8 + 1] = (uint8_t)(state[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(state[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(state[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(state[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(state[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(state[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(state[i]);
    }
}

void sentry_sha512_hex(const uint8_t *data, size_t len, char hex_out[129]) {
    uint8_t digest[64];
    sentry_sha512(data, len, digest);
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        hex_out[i * 2 + 0] = hex_chars[(digest[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    hex_out[128] = '\0';
}

int sentry_merkle_root(const char **leaf_hashes, size_t count, char root_out[129]) {
    if (count == 0) {
        sentry_sha512_hex((const uint8_t*)"EMPTY_MERKLE_ROOT", 17, root_out);
        return 0;
    }
    if (count == 1) {
        strncpy(root_out, leaf_hashes[0], 128);
        root_out[128] = '\0';
        return 1;
    }

    char **current = (char**)malloc(count * sizeof(char*));
    if (!current) return -1;
    for (size_t i = 0; i < count; i++) {
        current[i] = (char*)malloc(129);
        strncpy(current[i], leaf_hashes[i], 128);
        current[i][128] = '\0';
    }

    size_t cur_len = count;
    while (cur_len > 1) {
        size_t next_len = (cur_len + 1) / 2;
        char **next = (char**)malloc(next_len * sizeof(char*));
        if (!next) break;

        for (size_t i = 0; i < cur_len; i += 2) {
            size_t idx = i / 2;
            next[idx] = (char*)malloc(129);
            char combined[260];
            if (i + 1 < cur_len) {
                snprintf(combined, sizeof(combined), "%s%s", current[i], current[i + 1]);
            } else {
                snprintf(combined, sizeof(combined), "%s%s", current[i], current[i]);
            }
            sentry_sha512_hex((const uint8_t*)combined, strlen(combined), next[idx]);
        }

        for (size_t i = 0; i < cur_len; i++) free(current[i]);
        free(current);
        current = next;
        cur_len = next_len;
    }

    strncpy(root_out, current[0], 128);
    root_out[128] = '\0';
    free(current[0]);
    free(current);
    return 1;
}

void sentry_block_seal(int64_t index, const char *prev_hash, const char *merkle_root, int64_t timestamp_ms, const char *validator, char seal_out[129]) {
    char payload[1024];
    snprintf(payload, sizeof(payload), "%lld:%s:%s:%lld:%s",
             (long long)index,
             prev_hash ? prev_hash : "0",
             merkle_root ? merkle_root : "0",
             (long long)timestamp_ms,
             validator ? validator : "NTRO_VALIDATOR");
    sentry_sha512_hex((const uint8_t*)payload, strlen(payload), seal_out);
}
