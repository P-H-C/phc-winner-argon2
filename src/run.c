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

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "argon2.h"
#include "core.h"
#include "encoding.h"

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /*4 MB*/
#define LANES_DEF 4
#define THREADS_DEF 4
#define SALTLEN_DEF 16

#define UNUSED_PARAMETER(x) (void)(x)

static void usage(const char *cmd) {
    printf("Usage:  %s pwd salt [-y version] [-t t_cost] [-m m_cost] [-l "
           "#lanes] [-p #threads]\n",
           cmd);

    printf("Options:\n");
    printf("\tpwd\t\tThe password to hash (required)\n");
    printf("\tsalt\t\tThe salt to use, at most 16 characters (required)\n");
    printf("\t-y version\tArgon2 version, either d or i (default)\n");
    printf("\t-t t_cost\tNumber of rounds to t_cost between 1 and 2^24, "
           "default %d\n",
           T_COST_DEF);
    printf("\t-m m_cost\tMemory usage of 2^t_cost KiB, default %d\n",
           LOG_M_COST_DEF);
    printf("\t-p N\t\tParallelism, default %d\n", THREADS_DEF);
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

/*
Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
Base64-encoded hash string
@out output array with at least 32 bytes allocated
@pwd NULL-terminated string, presumably from argv[]
@salt salt array with at least SALTLEN_DEF bytes allocated
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
@type String, only "d" and "i" are accepted
*/
static void run(uint8_t *out, char *pwd, uint8_t *salt, uint32_t t_cost,
         uint32_t m_cost, uint32_t lanes, uint32_t threads, const char *type)
{
#if 0
    uint64_t start_cycles, stop_cycles;
    clock_t start_time, stop_time;
    double run_time, run_cycles;
#endif
    /*Fixed parameters*/
    const unsigned out_length = 32;
    const unsigned salt_length = SALTLEN_DEF;
    unsigned pwd_length;
    argon2_context context;
    char encoded[300];

#if 0
    start_time = clock();
    start_cycles = rdtsc();
#endif

    if (!pwd) {
        fatal("password missing");
    }

    if (!salt) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("salt missing");
    }

    pwd_length = strlen(pwd);

    UNUSED_PARAMETER(threads);

    context.out = out;
    context.outlen = out_length;
    context.pwd = (uint8_t *)pwd;
    context.pwdlen = pwd_length;
    context.salt = salt;
    context.saltlen = salt_length;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_FLAG_CLEAR_PASSWORD;

    if (!strcmp(type, "d"))
    {
        int result = argon2d(&context);
        if (result != ARGON2_OK) printf("%s\n",error_message(result));
    }
    else if (!strcmp(type, "i"))
    {
        int result = argon2i(&context);
        if (result != ARGON2_OK) printf("%s\n",error_message(result));
    }
    else {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("wrong Argon2 type");
    }

#if 0
    stop_cycles = rdtsc();
    stop_time = clock();
#endif

    /* show string encoding */
    encode_string(encoded, sizeof encoded, &context);
    printf("%s\n", encoded);

#if 0
    /* show running time/cycles */
    run_time = ((double)stop_time - start_time) / (CLOCKS_PER_SEC);
    run_cycles = (double)(stop_cycles - start_cycles) / (1UL << 20);
    printf("%2.3f seconds ", run_time);
    printf("(%.3f mebicycles)\n", run_cycles);
#endif
}



int main(int argc, char *argv[]) {
    unsigned char out[32];
    uint32_t m_cost = 1 << LOG_M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;
    char *pwd = NULL;
    uint8_t salt[SALTLEN_DEF];
    const char * type = "i";
    int i;

    if (argc < 3) {
        usage(argv[0]);
        return ARGON2_MISSING_ARGS;
    }

    /* get password and salt from command line */
    pwd = argv[1];
    if (strlen(argv[2]) > SALTLEN_DEF) {
        fatal("salt too long");
    }
    memset(salt, 0x00, SALTLEN_DEF); /* pad with null bytes */
    memcpy(salt, argv[2], strlen(argv[2]));

    /* parse options */
    for (i = 3; i < argc; i++) {
        const char *a = argv[i];
        unsigned long input = 0;
        if (!strcmp(a, "-m")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if( input == 0 || input == ULONG_MAX || input > ARGON2_MAX_MEMORY_BITS ) {
                    fatal("bad numeric input for -m");
                }
                m_cost = ARGON2_MIN(UINT64_C(1) << input, UINT32_C(0xFFFFFFFF));
                if( m_cost > ARGON2_MAX_MEMORY ) {
                    fatal("m_cost overflow");
                }
                continue;
            } else {
                fatal("missing -m argument");
            }
        } else if (!strcmp(a, "-t")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if( input == 0 || input == ULONG_MAX || input > ARGON2_MAX_TIME ) {
                    fatal("bad numeric input for -t");
                }
                t_cost = input;
                continue;
            } else {
                fatal("missing -t argument");
            }
        } else if (!strcmp(a, "-p")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if( input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_THREADS || input > ARGON2_MAX_LANES ) {
                    fatal("bad numeric input for -p");
                }
                threads = input;
                lanes = threads;
                continue;
            } else {
                fatal("missing -p argument");
            }
        } else if (!strcmp(a, "-y")) {
            if (i < argc - 1) {
                i++;
                if( strcmp(argv[i], "i") != 0 && strcmp(argv[i], "d") != 0 ) {
                    fatal("bad input to -y");
                }
                type = argv[i];
                continue;
            } else {
                fatal("missing -y argument");
            }
        } else {
            fatal("unknown argument");
        }
    }
    printf("Type:\t\tArgon2%c\n",type[0]);
    printf("Memory:\t\t%"PRIu32" KiB\n",m_cost);
    printf("Iterations:\t%"PRIu32" \n",t_cost);
    printf("Parallelism:\t%"PRIu32" \n",lanes);
    run(out, pwd, salt, t_cost, m_cost, lanes, threads, type);

    return ARGON2_OK;
}
