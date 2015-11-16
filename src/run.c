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

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUT_LEN 32
#define SALT_LEN 16
/* Sample encode: $argon2i$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY
 * Maximumum lengths are defined as:
 * strlen $argon2i$ = 9
 * m=65536 with strlen (uint32_t)-1 = 10, so this total is 12
 * ,t=2,p=4 If we consider each number to potentially reach four digits in future, this = 14
 * $c29tZXNhbHQAAAAAAAAAAA Formula for this is (SALT_LEN * 4 + 3) / 3 + 1 = 23
 * $QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY per above formula, = 44
 * + NULL byte
 * 9 + 12 + 14 + 23 + 44 + 1 = 103
 * Rounded to 4 byte boundary: 104
 *
 * WARNING: 104 is only for the parameters supported by this
   command-line utility. You'll need a longer ENCODED_LEN to support
   longer salts and ouputs, as supported by the argon2 library
 */
#define ENCODED_LEN 108

#define UNUSED_PARAMETER(x) (void)(x)

static void usage(const char *cmd) {
    printf("Usage:  %s salt [-d] [-t iterations] [-m memory] "
           "[-p parallelism]\n",
           cmd);
    printf("\tPassword is read from stdin\n");
    printf("Parameters:\n");
    printf("\tsalt\t\tThe salt to use, at most 16 characters\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i (which is the default)\n");
    printf("\t-t N\t\tSets the number of iterations to N (default = %d)\n",
           T_COST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n",
           LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N threads (default %d)\n",
           THREADS_DEF);
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
                uint32_t m_cost, uint32_t lanes, uint32_t threads,
                argon2_type type) {
    clock_t start_time, stop_time;
    size_t pwdlen;
    char encoded[ENCODED_LEN];
    uint32_t i;
    int result;

    start_time = clock();

    if (!pwd) {
        fatal("password missing");
    }

    if (!salt) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("salt missing");
    }

    pwdlen = strlen(pwd);

    UNUSED_PARAMETER(lanes);

    result = argon2_hash(t_cost, m_cost, threads, pwd, pwdlen, salt, SALT_LEN,
                         out, OUT_LEN, encoded, sizeof encoded, type);
    if (result != ARGON2_OK)
        fatal(error_message(result));

    stop_time = clock();

    printf("Hash:\t\t");
    for (i = 0; i < OUT_LEN; ++i) {
        printf("%02x", out[i]);
    }
    printf("\n");
    printf("Encoded:\t%s\n", encoded);

    printf("%2.3f seconds\n",
           ((double)stop_time - start_time) / (CLOCKS_PER_SEC));

    result = argon2_verify(encoded, pwd, pwdlen, type);
    if (result != ARGON2_OK)
        fatal(error_message(result));
    printf("Verification ok\n");
}

int main(int argc, char *argv[]) {
    unsigned char out[OUT_LEN];
    uint32_t m_cost = 1 << LOG_M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;
    uint8_t salt[SALT_LEN];
    argon2_type type = Argon2_i;
    int i;
    size_t n;
    char pwd[128];

    if (argc < 2) {
        usage(argv[0]);
        return ARGON2_MISSING_ARGS;
    }

    /* get password from stdin */
    while ((n = fread(pwd, 1, sizeof pwd - 1, stdin)) > 0) {
        pwd[n] = '\0';
        if (pwd[n - 1] == '\n')
            pwd[n - 1] = '\0';
    }

    /* get salt from command line */
    if (strlen(argv[1]) > SALT_LEN) {
        fatal("salt too long");
    }
    memset(salt, 0x00, SALT_LEN); /* pad with null bytes */
    memcpy(salt, argv[1], strlen(argv[1]));

    /* parse options */
    for (i = 2; i < argc; i++) {
        const char *a = argv[i];
        unsigned long input = 0;
        if (!strcmp(a, "-m")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_MEMORY_BITS) {
                    fatal("bad numeric input for -m");
                }
                m_cost = ARGON2_MIN(UINT64_C(1) << input, UINT32_C(0xFFFFFFFF));
                if (m_cost > ARGON2_MAX_MEMORY) {
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
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_TIME) {
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
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_THREADS || input > ARGON2_MAX_LANES) {
                    fatal("bad numeric input for -p");
                }
                threads = input;
                lanes = threads;
                continue;
            } else {
                fatal("missing -p argument");
            }
        } else if (!strcmp(a, "-d")) {
            type = Argon2_d;
        } else {
            fatal("unknown argument");
        }
    }
    if (type == Argon2_i) {
        printf("Type:\t\tArgon2i\n");
    } else {
        printf("Type:\t\tArgon2d\n");
    }
    printf("Iterations:\t%" PRIu32 " \n", t_cost);
    printf("Memory:\t\t%" PRIu32 " KiB\n", m_cost);
    printf("Parallelism:\t%" PRIu32 " \n", lanes);
    run(out, pwd, salt, t_cost, m_cost, lanes, threads, type);

    return ARGON2_OK;
}
