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
#pragma once

#ifndef __ARGON2_H__
#define __ARGON2_H__

#include "stddef.h"
#include "stdbool.h"

/************************* Constants to enable Known Answer Tests (KAT)  **************************************************/
/* Enable ARGON2_KAT */
//#define ARGON2_KAT
//#define ARGON2_KAT_INTERNAL


/* The KAT file name */
extern const char* ARGON2_KAT_FILENAME;


/*************************Argon2 input parameter restrictions**************************************************/

/* Minimum and maximum number of lanes (degree of parallelism) */
extern const uint32_t ARGON2_MIN_LANES ;
extern const uint32_t ARGON2_MAX_LANES;

extern const uint32_t ARGON2_MIN_THREADS ;
extern const uint32_t ARGON2_MAX_THREADS;

/* Number of synchronization points between lanes per pass */
#define __ARGON_SYNC_POINTS 4
extern const uint32_t ARGON2_SYNC_POINTS;

/* Minimum and maximum digest size in bytes */
extern const uint32_t ARGON2_MIN_OUTLEN ;
extern const uint32_t ARGON2_MAX_OUTLEN ;

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
extern const uint32_t ARGON2_MIN_MEMORY ; // 2 blocks per slice
extern const uint32_t ARGON2_MAX_MEMORY; // 2^32-1 blocks

/* Minimum and maximum number of passes */
extern const uint32_t ARGON2_MIN_TIME ;
extern const uint32_t ARGON2_MAX_TIME;

/* Minimum and maximum password length in bytes */
extern const uint32_t ARGON2_MIN_PWD_LENGTH ;
extern const uint32_t ARGON2_MAX_PWD_LENGTH ;

/* Minimum and maximum associated data length in bytes */
extern const uint32_t ARGON2_MIN_AD_LENGTH ;
extern const uint32_t ARGON2_MAX_AD_LENGTH ;

/* Minimum and maximum salt length in bytes */
extern const uint32_t ARGON2_MIN_SALT_LENGTH ;
extern  const uint32_t ARGON2_MAX_SALT_LENGTH;

/* Minimum and maximum key length in bytes */
extern const uint32_t ARGON2_MIN_SECRET ;
extern const uint32_t ARGON2_MAX_SECRET ;

/************************* Error codes *********************************************************************************/
typedef enum _Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = 1,

    ARGON2_OUTPUT_TOO_SHORT = 2,
    ARGON2_OUTPUT_TOO_LONG = 3,

    ARGON2_PWD_TOO_SHORT = 4,
    ARGON2_PWD_TOO_LONG = 5,

    ARGON2_SALT_TOO_SHORT = 6,
    ARGON2_SALT_TOO_LONG = 7,

    ARGON2_AD_TOO_SHORT = 8,
    ARGON2_AD_TOO_LONG = 9,

    ARGON2_SECRET_TOO_SHORT = 10,
    ARGON2_SECRET_TOO_LONG = 11,

    ARGON2_TIME_TOO_SMALL = 12,
    ARGON2_TIME_TOO_LARGE = 13,

    ARGON2_MEMORY_TOO_LITTLE = 14,
    ARGON2_MEMORY_TOO_MUCH = 15,

    ARGON2_LANES_TOO_FEW = 16,
    ARGON2_LANES_TOO_MANY = 17,

    ARGON2_PWD_PTR_MISMATCH = 18, //NULL ptr with non-zero length
    ARGON2_SALT_PTR_MISMATCH = 19, //NULL ptr with non-zero length
    ARGON2_SECRET_PTR_MISMATCH = 20, //NULL ptr with non-zero length
    ARGON2_AD_PTR_MISMATCH = 21, //NULL ptr with non-zero length

    ARGON2_MEMORY_ALLOCATION_ERROR = 22,

    ARGON2_FREE_MEMORY_CBK_NULL = 23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = 24,

    ARGON2_INCORRECT_PARAMETER = 25,
    ARGON2_INCORRECT_TYPE = 26,

    ARGON2_OUT_PTR_MISMATCH = 27,
            
    ARGON2_THREADS_TOO_FEW = 28,
    ARGON2_THREADS_TOO_MANY = 29,

    ARGON2_ERROR_CODES_LENGTH /* Do NOT remove; Do NOT add error codes after this error code */
} Argon2_ErrorCodes;



/********************************************* Memory allocator types --- for external allocation *************************************************************/
typedef int (*AllocateMemoryCallback)(uint8_t **memory, size_t bytes_to_allocate);
typedef void(*FreeMemoryCallback)(uint8_t *memory, size_t bytes_to_allocate);

/********************************************* Argon2 external data structures*************************************************************/

/*
 *****Context: structure to hold Argon2 inputs: 
 * output array and its length, 
 * password and its length,
 * salt and its length,
 * secret and its length,
 * associated data and its length,
 * number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 * number of parallel threads that will be run.
 * All the parameters above affect the output hash value.
 * Additionally, two function pointers can be provided to allocate and deallocate the memory (if NULL, memory will be allocated internally).
 * Also, three flags indicate whether to erase password, secret as soon as they are pre-hashed (and thus not needed anymore), and the entire memory
 ****************************
 Simplest situation: you have output array out[8], password is stored in pwd[32], salt is stored in salt[16], you do not have keys nor associated data.
 You need to spend 1 GB of RAM and you run 5 passes of Argon2d with 4 parallel lanes.
 You want to erase the password, but you're OK with last pass not being erased.
 You want to use the default memory allocator.
 Then you initialize
 Argon2_Context(out,8,pwd,32,salt,16,NULL,0,NULL,0,5,1<<20,4,NULL,NULL,true,false,false).
 */
typedef struct _Argon2_Context {
    uint8_t *out; //output array
    const uint32_t outlen; //digest length

    uint8_t *pwd; //password array
    uint32_t pwdlen; //password length

    const uint8_t *salt; //salt array
    const uint32_t saltlen; //salt length

    uint8_t *secret; //key array
    uint32_t secretlen; //key length

    const uint8_t *ad; //associated data array
    const uint32_t adlen; //associated data length

    const uint32_t t_cost; //number of passes
    const uint32_t m_cost; //amount of memory requested (KB)
    const uint32_t lanes; //number of lanes
    const uint32_t threads; //maximum number of threads

    AllocateMemoryCallback allocate_cbk; //pointer to memory allocator
    FreeMemoryCallback free_cbk; //pointer to memory deallocator

    const bool clear_password; //whether to clear the password array
    const bool clear_secret; //whether to clear the secret array
    const bool clear_memory; //whether to clear the memory after the run
    
    const bool print; //whether to print starting variables, memory blocks, and the tag to the file -- Test vectors only!
    
} Argon2_Context;



/**
 * Function to hash the inputs in the memory-hard fashion
 * @param  out  Pointer to the memory where the hash digest will be written
 * @param  outlen Digest length in bytes
 * @param  in Pointer to the input (password)
 * @param  inlen Input length in bytes
 * @param  salt Pointer to the salt
 * @param  saltlen Salt length in bytes
 * @pre    @a out must have at least @a outlen bytes allocated
 * @pre    @a in must be at least @inlen bytes long
 * @pre    @a saltlen must be at least @saltlen bytes long
 * @return Zero if successful, 1 otherwise.
 */
extern  int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost);

/*
 * **************Argon2d: Version of Argon2 that picks memory blocks depending on the password and salt. Only for side-channel-free environment!!***************
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int Argon2d(Argon2_Context* context);

/*
 *  * **************Argon2i: Version of Argon2 that picks memory blocks independent on the password and salt. Good for side-channels,
 ******************* but worse w.r.t. tradeoff attacks if
 *******************only one pass is used***************
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int Argon2i(Argon2_Context* context);

/*
 *   * **************Argon2di: Reserved name***************
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int Argon2di(Argon2_Context* context);

/*
 *   * **************Argon2ds: Argon2d hardened against GPU attacks, 20% slower***************
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int Argon2ds(Argon2_Context* context);


/*
 *   * **************Argon2id: First half-pass over memory is password-independent, the rest are password-dependent
 ********************OK against side channels: they reduce to 1/2-pass Argon2i***************
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int Argon2id(Argon2_Context* context);

/*
 * Verify if a given password is correct for Argon2d hashing
 * @param  context  Pointer to current Argon2 context
 * @param  hash  The password hash to verify. The length of the hash is specified by the context outlen member
 * @return  Zero if successful, a non zero error code otherwise
 */
extern int VerifyD(Argon2_Context* context, const char *hash);

/*
 * Get the associated error message for given error code
 * @return  The error message associated with the given error code
 */
const char* ErrorMessage(int error_code);

#endif
