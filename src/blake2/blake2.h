/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#ifndef BLAKE2_H
#define BLAKE2_H

#include <stddef.h>
#include <stdint.h>

/* Argon2 Team - Begin Code */
#if defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((__aligned__(x)))
#endif
/* Argon2 Team - End Code */

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __blake2b_param {
    uint8_t digest_length;                   // 1
    uint8_t key_length;                      // 2
    uint8_t fanout;                          // 3
    uint8_t depth;                           // 4
    uint32_t leaf_length;                    // 8
    uint64_t node_offset;                    // 16
    uint8_t node_depth;                      // 17
    uint8_t inner_length;                    // 18
    uint8_t reserved[14];                    // 32
    uint8_t salt[BLAKE2B_SALTBYTES];         // 48
    uint8_t personal[BLAKE2B_PERSONALBYTES]; // 64
} blake2b_param;

ALIGN(64) typedef struct __blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[2 * BLAKE2B_BLOCKBYTES];
    size_t buflen;
    uint8_t last_node;
} blake2b_state;

#pragma pack(pop)

int blake2b_init(blake2b_state *S, const uint8_t outlen);
int blake2b_init_key(blake2b_state *S, const uint8_t outlen, const void *key,
                     const uint8_t keylen);
int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
int blake2b_update(blake2b_state *S, const uint8_t *in, uint64_t inlen);
int blake2b_final(blake2b_state *S, uint8_t *out, uint8_t outlen);

int blake2b(uint8_t *out, const void *in, const void *key, const uint8_t outlen,
            const uint64_t inlen, uint8_t keylen);
/* Argon2 Team - Begin Code */
int blake2b_long(uint8_t *out, const void *in, const uint32_t outlen,
                 const uint64_t inlen);
/* Argon2 Team - End Code */

#if defined(__cplusplus)
}
#endif

#endif
