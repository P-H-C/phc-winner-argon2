#include <stdio.h>
#include <string.h>
#include "encoding.h"

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 */
#define EQ(x, y) ((((0U - ((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

/*
 * Convert value x (0..63) to corresponding Base64 character.
 */
static int b64_byte_to_char(unsigned x) {
    return (LT(x, 26) & (x + 'A')) |
           (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
           (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
           (EQ(x, 63) & '/');
}

/*
 * Convert some bytes to Base64. 'dst_len' is the length (in characters)
 * of the output buffer 'dst'; if that buffer is not large enough to
 * receive the result (including the terminating 0), then (size_t)-1
 * is returned. Otherwise, the zero-terminated Base64 string is written
 * in the buffer, and the output length (counted WITHOUT the terminating
 * zero) is returned.
 */
static size_t to_base64(char *dst, size_t dst_len, const void *src,
                        size_t src_len) {
    size_t olen;
    const unsigned char *buf;
    unsigned acc, acc_len;

    olen = (src_len / 3) << 2;
    switch (src_len % 3) {
    case 2:
        olen++;
    /* fall through */
    case 1:
        olen += 2;
        break;
    }
    if (dst_len <= olen) {
        return (size_t)-1;
    }
    acc = 0;
    acc_len = 0;
    buf = (const unsigned char *)src;
    while (src_len-- > 0) {
        acc = (acc << 8) + (*buf++);
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            *dst++ = b64_byte_to_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        *dst++ = b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
    *dst++ = 0;
    return olen;
}

/* ==================================================================== */
/*
 * Code specific to Argon2i.
 *
 * The code below applies the following format:
 *
 *  $argon2i$m=<num>,t=<num>,p=<num>[,keyid=<bin>][,data=<bin>][$<bin>[$<bin>]]
 *
 * where <num> is a decimal integer (positive, fits in an 'unsigned long')
 * and <bin> is Base64-encoded data (no '=' padding characters, no newline
 * or whitespace). The "keyid" is a binary identifier for a key (up to 8
 * bytes); "data" is associated data (up to 32 bytes). When the 'keyid'
 * (resp. the 'data') is empty, then it is ommitted from the output.
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are optional, but you cannot have an
 * output without a salt. The binary salt length is between 8 and 48 bytes.
 * The output length is always exactly 32 bytes.
 */

int encode_string(char *dst, size_t dst_len, argon2_context *ctx,
argon2_type type) {
#define SS(str)                                                                \
    do {                                                                       \
        size_t pp_len = strlen(str);                                           \
        if (pp_len >= dst_len) {                                               \
            return 0;                                                          \
        }                                                                      \
        memcpy(dst, str, pp_len + 1);                                          \
        dst += pp_len;                                                         \
        dst_len -= pp_len;                                                     \
    } while (0)

#define SX(x)                                                                  \
    do {                                                                       \
        char tmp[30];                                                          \
        sprintf(tmp, "%lu", (unsigned long)(x));                               \
        SS(tmp);                                                               \
    } while (0);

#define SB(buf, len)                                                           \
    do {                                                                       \
        size_t sb_len = to_base64(dst, dst_len, buf, len);                     \
        if (sb_len == (size_t)-1) {                                            \
            return 0;                                                          \
        }                                                                      \
        dst += sb_len;                                                         \
        dst_len -= sb_len;                                                     \
    } while (0);

    SS("$argon2i$m=");
    SX(ctx->m_cost);
    SS(",t=");
    SX(ctx->t_cost);
    SS(",p=");
    SX(ctx->lanes);

    if (ctx->adlen > 0) {
        SS(",data=");
        SB(ctx->ad, ctx->adlen);
    }

    if (ctx->saltlen == 0)
        return 1;

    SS("$");
    SB(ctx->salt, ctx->saltlen);

    if (ctx->outlen == 0)
        return 1;

    SS("$");
    SB(ctx->out, ctx->outlen);
    return 1;

#undef SS
#undef SX
#undef SB
}
