/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "argon2.h"
#include "encoding.h"
#include "core.h"

/* Error messages */
static const char *Argon2_ErrorMessage[] = {
    /*{ARGON2_OK, */ "OK",
    /*},

    {ARGON2_OUTPUT_PTR_NULL, */ "Output pointer is NULL",
    /*},

{ARGON2_OUTPUT_TOO_SHORT, */ "Output is too short",
    /*},
{ARGON2_OUTPUT_TOO_LONG, */ "Output is too long",
    /*},

{ARGON2_PWD_TOO_SHORT, */ "Password is too short",
    /*},
{ARGON2_PWD_TOO_LONG, */ "Password is too long",
    /*},

{ARGON2_SALT_TOO_SHORT, */ "Salt is too short",
    /*},
{ARGON2_SALT_TOO_LONG, */ "Salt is too long",
    /*},

{ARGON2_AD_TOO_SHORT, */ "Associated data is too short",
    /*},
{ARGON2_AD_TOO_LONG, */ "Associated date is too long",
    /*},

{ARGON2_SECRET_TOO_SHORT, */ "Secret is too short",
    /*},
{ARGON2_SECRET_TOO_LONG, */ "Secret is too long",
    /*},

{ARGON2_TIME_TOO_SMALL, */ "Time cost is too small",
    /*},
{ARGON2_TIME_TOO_LARGE, */ "Time cost is too large",
    /*},

{ARGON2_MEMORY_TOO_LITTLE, */ "Memory cost is too small",
    /*},
{ARGON2_MEMORY_TOO_MUCH, */ "Memory cost is too large",
    /*},

{ARGON2_LANES_TOO_FEW, */ "Too few lanes",
    /*},
{ARGON2_LANES_TOO_MANY, */ "Too many lanes",
    /*},

{ARGON2_PWD_PTR_MISMATCH, */ "Password pointer is NULL, but password length is not 0",
    /*},
{ARGON2_SALT_PTR_MISMATCH, */ "Salt pointer is NULL, but salt length is not 0",
    /*},
{ARGON2_SECRET_PTR_MISMATCH, */ "Secret pointer is NULL, but secret length is not 0",
    /*},
{ARGON2_AD_PTR_MISMATCH, */ "Associated data pointer is NULL, but ad length is not 0",
    /*},

{ARGON2_MEMORY_ALLOCATION_ERROR, */ "Memory allocation error",
    /*},

{ARGON2_FREE_MEMORY_CBK_NULL, */ "The free memory callback is NULL",
    /*},
{ARGON2_ALLOCATE_MEMORY_CBK_NULL, */ "The allocate memory callback is NULL",
    /*},

{ARGON2_INCORRECT_PARAMETER, */ "Argon2_Context context is NULL",
    /*},
{ARGON2_INCORRECT_TYPE, */ "There is no such version of Argon2",
    /*},

{ARGON2_OUT_PTR_MISMATCH, */ "Output pointer mismatch",
    /*},

{ARGON2_THREADS_TOO_FEW, */ "Not enough threads",
    /*},
{ARGON2_THREADS_TOO_MANY, */ "Too many threads",
    /*},
{ARGON2_MISSING_ARGS, */ "Missing arguments",
    /*},
{ARGON2_ENCODING_FAIL, */ "Encoding failed",
    /*},
{ARGON2_DECODING_FAIL, */ "Decoding failed", /*},*/
};

int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen, char *encoded,
                const size_t encodedlen, argon2_type type) {

    argon2_context context;
    int result;
    uint8_t *out;

    /* Detect and reject overflowing sizes */
    /* TODO: This should probably be fixed in the function signature */
    if (pwdlen > UINT32_MAX) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (hashlen > UINT32_MAX) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (saltlen > UINT32_MAX) {
        return ARGON2_SALT_TOO_LONG;
    }

    out = malloc(hashlen);
    if (!out) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)hashlen;
    context.pwd = (uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    result = argon2_core(&context, type);

    if (result != ARGON2_OK) {
        memset(out, 0x00, hashlen);
        free(out);
        return result;
    }

    /* if raw hash requested, write it */
    if (hash) {
        memcpy(hash, out, hashlen);
    }

    /* if encoding requested, write it */
    if (encoded && encodedlen) {
        if (!encode_string(encoded, encodedlen, &context, type)) {
            memset(out, 0x00, hashlen);
            memset(encoded, 0x00, encodedlen);
            free(out);
            return ARGON2_ENCODING_FAIL;
        }
    }

    free(out);

    return ARGON2_OK;
}

int argon2i_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
                         const uint32_t parallelism, const void *pwd,
                         const size_t pwdlen, const void *salt,
                         const size_t saltlen, const size_t hashlen,
                         char *encoded, const size_t encodedlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       NULL, hashlen, encoded, encodedlen, Argon2_i);
}

int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       hash, hashlen, NULL, 0, Argon2_i);
}

int argon2d_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
                         const uint32_t parallelism, const void *pwd,
                         const size_t pwdlen, const void *salt,
                         const size_t saltlen, const size_t hashlen,
                         char *encoded, const size_t encodedlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       NULL, hashlen, encoded, encodedlen, Argon2_d);
}

int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       hash, hashlen, NULL, 0, Argon2_d);
}

int argon2_compare(const uint8_t *b1, const uint8_t *b2, size_t len) {
    size_t i;
    uint8_t d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int)((1 & ((d - 1) >> 8)) - 1);
}

int argon2_verify(const char *encoded, const void *pwd, const size_t pwdlen,
                  argon2_type type) {

    argon2_context ctx;
    uint8_t *out;
    int ret;

    /* max values, to be updated in decode_string */
    ctx.adlen = 512;
    ctx.saltlen = 512;
    ctx.outlen = 512;

    ctx.ad = malloc(ctx.adlen);
    ctx.salt = malloc(ctx.saltlen);
    ctx.out = malloc(ctx.outlen);
    if (!ctx.out || !ctx.salt || !ctx.ad) {
        free(ctx.ad);
        free(ctx.salt);
        free(ctx.out);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    out = malloc(ctx.outlen);
    if (!out) {
        free(ctx.ad);
        free(ctx.salt);
        free(ctx.out);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if(decode_string(&ctx, encoded, type) != 1) {
        free(ctx.ad);
        free(ctx.salt);
        free(ctx.out);
        free(out);
        return ARGON2_DECODING_FAIL;
    }

    ret = argon2_hash(ctx.t_cost, ctx.m_cost, ctx.threads, pwd, pwdlen, ctx.salt,
                ctx.saltlen, out, ctx.outlen, NULL, 0, type);

    free(ctx.ad);
    free(ctx.salt);

    if (ret != ARGON2_OK || argon2_compare(out, ctx.out, ctx.outlen)) {
        free(out);
        free(ctx.out);
        return ARGON2_DECODING_FAIL;
    }
    free(out);
    free(ctx.out);

    return ARGON2_OK;
}

int argon2i_verify(const char *encoded, const void *pwd, const size_t pwdlen) {

    return argon2_verify(encoded, pwd, pwdlen, Argon2_i);
}

int argon2d_verify(const char *encoded, const void *pwd, const size_t pwdlen) {

    return argon2_verify(encoded, pwd, pwdlen, Argon2_d);
}

int argon2d(argon2_context *context) { return argon2_core(context, Argon2_d); }

int argon2i(argon2_context *context) { return argon2_core(context, Argon2_i); }

int verify_d(argon2_context *context, const char *hash) {
    int result;
    if (0 == context->outlen || NULL == hash) {
        return ARGON2_OUT_PTR_MISMATCH;
    }

    result = argon2_core(context, Argon2_d);

    if (ARGON2_OK != result) {
        return result;
    }

    return 0 == memcmp(hash, context->out, context->outlen);
}

const char *error_message(int error_code) {
    enum {
        /* Make sure---at compile time---that the enum size matches the array
           size */
        ERROR_STRING_CHECK =
            1 /
            !!((sizeof(Argon2_ErrorMessage) / sizeof(Argon2_ErrorMessage[0])) ==
               ARGON2_ERROR_CODES_LENGTH)
    };
    if (error_code < ARGON2_ERROR_CODES_LENGTH) {
        return Argon2_ErrorMessage[(argon2_error_codes)error_code];
    }
    return "Unknown error code.";
}
