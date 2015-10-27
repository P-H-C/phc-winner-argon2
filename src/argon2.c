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
#include <stdio.h>

#include "argon2.h"
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

{ARGON2_OUT_PTR_MISMATCH, */ "Output pointer mismatch" /*}*/
};

int hash_argon2i(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {

    argon2_context context;
    context.out = (uint8_t *)out;
    context.outlen = outlen;
    context.pwd = (uint8_t *)in;
    context.pwdlen = inlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = 1;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    return argon2_core(&context, Argon2_i);
}

int hash_argon2d(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {

    argon2_context context;
    context.out = (uint8_t *)out;
    context.outlen = outlen;
    context.pwd = (uint8_t *)in;
    context.pwdlen = inlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = 1;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    return argon2_core(&context, Argon2_d);
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
    if (error_code < ARGON2_ERROR_CODES_LENGTH) {
        return Argon2_ErrorMessage[(argon2_error_codes)error_code];
    }
    return "Unknown error code.";
}
