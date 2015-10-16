/*
 * Argon2 source code package
 * 
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 * 
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include "stdint.h" 
#include "stdbool.h"
#include <string.h>
#include "stdio.h"

#include "argon2.h"
#include "argon2-core.h"


/*************************Argon2 input parameter restrictions**************************************************/

/* Minimum and maximum number of lanes (degree of parallelism) */
const uint32_t ARGON2_MIN_LANES = 1;
const uint32_t ARGON2_MAX_LANES = 0xFFFFFF;

/* Minimum and maximum number of threads */
const uint32_t ARGON2_MIN_THREADS = 1;
const uint32_t ARGON2_MAX_THREADS = 0xFFFFFF;

/* Number of synchronization points between lanes per pass */
#define __ARGON_SYNC_POINTS 4
const uint32_t ARGON2_SYNC_POINTS = __ARGON_SYNC_POINTS;

/* Minimum and maximum digest size in bytes */
const uint32_t ARGON2_MIN_OUTLEN = 4;
const uint32_t ARGON2_MAX_OUTLEN = 0xFFFFFFFF;

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
const uint32_t ARGON2_MIN_MEMORY = 2 * __ARGON_SYNC_POINTS; // 2 blocks per slice
const uint32_t ARGON2_MAX_MEMORY = 0xFFFFFFFF; // 2^32-1 blocks

/* Minimum and maximum number of passes */
const uint32_t ARGON2_MIN_TIME = 1;
const uint32_t ARGON2_MAX_TIME = 0xFFFFFFFF;

/* Minimum and maximum password length in bytes */
const uint32_t ARGON2_MIN_PWD_LENGTH = 0;
const uint32_t ARGON2_MAX_PWD_LENGTH = 0xFFFFFFFF;

/* Minimum and maximum associated data length in bytes */
const uint32_t ARGON2_MIN_AD_LENGTH = 0;
const uint32_t ARGON2_MAX_AD_LENGTH = 0xFFFFFFFF;

/* Minimum and maximum salt length in bytes */
const uint32_t ARGON2_MIN_SALT_LENGTH = 8;
const uint32_t ARGON2_MAX_SALT_LENGTH = 0xFFFFFFFF;

/* Minimum and maximum key length in bytes */
const uint32_t ARGON2_MIN_SECRET = 0;
const uint32_t ARGON2_MAX_SECRET = 0xFFFFFFFF;


/************************* Error messages *********************************************************************************/

const char* Argon2_ErrorMessage[] = {
    /*{ARGON2_OK, */"OK",/*},

    {ARGON2_OUTPUT_PTR_NULL, */"Output pointer is NULL",/*},

    {ARGON2_OUTPUT_TOO_SHORT, */"Output is too short",/*},
    {ARGON2_OUTPUT_TOO_LONG, */"Output is too long",/*},

    {ARGON2_PWD_TOO_SHORT, */"Password is too short",/*},
    {ARGON2_PWD_TOO_LONG, */"Password is too long",/*},

    {ARGON2_SALT_TOO_SHORT, */"Salt is too short",/*},
    {ARGON2_SALT_TOO_LONG, */"Salt is too long",/*},

    {ARGON2_AD_TOO_SHORT, */"Associated data is too short",/*},
    {ARGON2_AD_TOO_LONG, */"Associated date is too long",/*},

    {ARGON2_SECRET_TOO_SHORT, */"Secret is too short",/*},
    {ARGON2_SECRET_TOO_LONG, */"Secret is too long",/*},

    {ARGON2_TIME_TOO_SMALL, */"Time cost is too small",/*},
    {ARGON2_TIME_TOO_LARGE, */"Time cost is too large",/*},

    {ARGON2_MEMORY_TOO_LITTLE, */"Memory cost is too small",/*},
    {ARGON2_MEMORY_TOO_MUCH, */"Memory cost is too large",/*},

    {ARGON2_LANES_TOO_FEW, */"Too few lanes",/*},
    {ARGON2_LANES_TOO_MANY, */"Too many lanes",/*},

    {ARGON2_PWD_PTR_MISMATCH, */"Password pointer is NULL, but password length is not 0",/*},
    {ARGON2_SALT_PTR_MISMATCH, */"Salt pointer is NULL, but salt length is not 0",/*},
    {ARGON2_SECRET_PTR_MISMATCH, */"Secret pointer is NULL, but secret length is not 0",/*},
    {ARGON2_AD_PTR_MISMATCH, */"Associated data pointer is NULL, but ad length is not 0",/*},

    {ARGON2_MEMORY_ALLOCATION_ERROR, */"Memory allocation error",/*},

    {ARGON2_FREE_MEMORY_CBK_NULL, */"The free memory callback is NULL",/*},
    {ARGON2_ALLOCATE_MEMORY_CBK_NULL, */"The allocate memory callback is NULL",/*},

    {ARGON2_INCORRECT_PARAMETER, */"Argon2_Context context is NULL",/*},
    {ARGON2_INCORRECT_TYPE, */"There is no such version of Argon2",/*},
    
    {ARGON2_OUT_PTR_MISMATCH, */"Output pointer mismatch"/*}*/
};

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, 
        size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
    uint8_t* default_ad_ptr = NULL;
    uint32_t default_ad_length = 0;
    uint8_t* default_secret_ptr = NULL;
    uint32_t default_secret_length = 0;
    uint8_t default_parallelism = 1;
    AllocateMemoryCallback default_a_cbk = NULL;
    FreeMemoryCallback default_f_cbk= NULL;
    bool c_p=true;
    bool c_s=true;
    bool c_m=false;
    bool pr=false;

    Argon2_Context context = {(uint8_t*) out, (uint32_t) outlen,
            (uint8_t*) in, (uint32_t) inlen,
            (uint8_t*) salt, (uint32_t) saltlen,
            default_ad_ptr, default_ad_length,
            default_secret_ptr, default_secret_length,
            (uint32_t) t_cost, (uint32_t) m_cost, default_parallelism,default_parallelism,default_a_cbk,default_f_cbk,
    c_p,c_s,c_m,pr};

    return Argon2Core(&context, Argon2_d);
}

int Argon2d(Argon2_Context* context) {
    return Argon2Core(context, Argon2_d);
}

int Argon2i(Argon2_Context* context) {
    return Argon2Core(context, Argon2_i);
}

int Argon2id(Argon2_Context* context) {
    return Argon2Core(context, Argon2_id);
}

int Argon2ds(Argon2_Context* context) {
    return Argon2Core(context, Argon2_ds);
}

int VerifyD(Argon2_Context* context, const char *hash) {
    if (0 == context->outlen || NULL == hash) {
        return ARGON2_OUT_PTR_MISMATCH;
    }

    int result = Argon2Core(context, Argon2_d);
    if (ARGON2_OK != result) {
        return result;
    }

    return 0 == memcmp(hash, context->out, context->outlen);
}

const char* ErrorMessage(int error_code) {
    if (error_code < ARGON2_ERROR_CODES_LENGTH) {
        return Argon2_ErrorMessage[(Argon2_ErrorCodes) error_code];
    }

    return "Unknown error code.";
}
