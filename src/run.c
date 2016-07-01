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

#define _GNU_SOURCE 1

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "argon2.h"
#include "core.h"

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUTLEN_DEF 32
#define MAX_PASS_LEN 128

#define UNUSED_PARAMETER(x) (void)(x)

static void usage(const char *cmd) {
    printf("Usage:  %s [-h] salt [-d] [-t iterations] [-m memory] "
           "[-p parallelism] [-n threads] [-l hash length] [-e|-r]\n",
           cmd);
    printf("\tPassword is read from stdin\n");
    printf("Parameters:\n");
    printf("\tsalt\t\tThe salt to use, at least 8 characters\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i (which is the default)\n");
    printf("\t-t N\t\tSets the number of iterations to N (default = %d)\n",
           T_COST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n",
           LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N lanes (default %d)\n",
           THREADS_DEF);
    printf("\t-n N\t\tSets parallelism to N threads (default %d)\n",
           THREADS_DEF);
    printf("\t-l N\t\tSets hash output length to N bytes (default %d)\n",
           OUTLEN_DEF);
    printf("\t-e\t\tOutput only encoded hash\n");
    printf("\t-r\t\tOutput only the raw bytes of the hash\n");
    printf("\t-h\t\tPrint %s usage\n", cmd);
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

static void print_hex(uint8_t *bytes, size_t bytes_len) {
    size_t i;
    for (i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/*
Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
Base64-encoded hash string
@out output array with at least 32 bytes allocated
@pwd NULL-terminated string, presumably from argv[]
@salt salt array
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
@type String, only "d" and "i" are accepted
@encoded_only display only the encoded hash
@raw_only display only the hexadecimal of the hash
*/
static void run(uint32_t outlen, char *pwd, char *salt, uint32_t t_cost,
                uint32_t m_cost, uint32_t lanes, uint32_t threads,
                argon2_type type, int encoded_only, int raw_only) {
    clock_t start_time, stop_time;
    size_t pwdlen, saltlen, encodedlen;
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
    saltlen = strlen(salt);
    if(UINT32_MAX < saltlen) {
        fatal("salt is too long");
    }

    UNUSED_PARAMETER(lanes);

    unsigned char* out = malloc(outlen + 1);
    if (!out) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("could not allocate memory for output");
    }

    encodedlen = argon2_encodedlen(t_cost, m_cost, lanes, (uint32_t)saltlen, outlen);
    char* encoded = malloc(encodedlen + 1);
    if (!encoded) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("could not allocate memory for hash");
    }

    result = argon2_hash(t_cost, m_cost, threads, lanes, pwd, pwdlen, salt, saltlen,
                         out, outlen, encoded, encodedlen, type,
                         ARGON2_VERSION_NUMBER);
    if (result != ARGON2_OK)
        fatal(argon2_error_message(result));

    stop_time = clock();

    if (encoded_only)
        puts(encoded);

    if (raw_only)
        print_hex(out, outlen);

    if (encoded_only || raw_only) {
        free(out);
        free(encoded);
        return;
    }

    printf("Hash:\t\t");
    print_hex(out, outlen);
    free(out);

    printf("Encoded:\t%s\n", encoded);

    printf("%2.3f seconds\n",
           ((double)stop_time - start_time) / (CLOCKS_PER_SEC));

    result = argon2_verify(encoded, pwd, pwdlen, type);
    if (result != ARGON2_OK)
        fatal(argon2_error_message(result));
    printf("Verification ok\n");
    free(encoded);
}

int main(int argc, char *argv[]) {
    uint32_t outlen = OUTLEN_DEF;
    uint32_t m_cost = 1 << LOG_M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;
    argon2_type type = Argon2_i;
    int encoded_only = 0;
    int raw_only = 0;
    int i;
    size_t n;
    char pwd[MAX_PASS_LEN], *salt;

    if (argc < 2) {
        usage(argv[0]);
        return ARGON2_MISSING_ARGS;
    } else if (argc >= 2 && strcmp(argv[1], "-h") == 0) {
        usage(argv[0]);
        return 1;
    }

    /* get password from stdin */
    n = fread(pwd, 1, sizeof pwd - 1, stdin);
    if(n < 1) {
        fatal("no password read");
    }
    if(n == MAX_PASS_LEN-1) {
        fatal("Provided password longer than supported in command line utility");
    }

    pwd[n] = '\0';
    if (pwd[n - 1] == '\n') {
        pwd[n - 1] = '\0';
    }

    salt = argv[1];

    /* parse options */
    for (i = 2; i < argc; i++) {
        const char *a = argv[i];
        unsigned long input = 0;
        if (!strcmp(a, "-h")) {
            usage(argv[0]);
            return 1;
        } else if (!strcmp(a, "-m")) {
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
        } else if (!strcmp(a, "-n")) {
	    if (i < argc - 1) {
		i++;
		input = strtoul(argv[i], NULL, 10);
		if (input == 0 || input == ULONG_MAX ||
		    input > ARGON2_MAX_THREADS) {
		    fatal("bad numeric input for -n");
		}
		threads = input;
		continue;
	    }
        } else if (!strcmp(a, "-p")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                if (input == 0 || input == ULONG_MAX ||
                    input > ARGON2_MAX_LANES) {
                    fatal("bad numeric input for -p");
                }
                lanes = input;
                continue;
            } else {
                fatal("missing -p argument");
            }
        } else if (!strcmp(a, "-l")) {
            if (i < argc - 1) {
                i++;
                input = strtoul(argv[i], NULL, 10);
                outlen = input;
                continue;
            } else {
                fatal("missing -l argument");
            }
        } else if (!strcmp(a, "-d")) {
            type = Argon2_d;
        } else if (!strcmp(a, "-e")) {
            encoded_only = 1;
        } else if (!strcmp(a, "-r")) {
            raw_only = 1;
        } else {
            fatal("unknown argument");
        }
    }

    if(encoded_only && raw_only)
        fatal("cannot provide both -e and -r");

    if(!encoded_only && !raw_only) {
        if (type == Argon2_i) {
            printf("Type:\t\tArgon2i\n");
        } else {
            printf("Type:\t\tArgon2d\n");
        }
        printf("Iterations:\t%" PRIu32 " \n", t_cost);
        printf("Memory:\t\t%" PRIu32 " KiB\n", m_cost);
        printf("Parallelism:\t%" PRIu32 " \n", lanes);
    }

    run(outlen, pwd, salt, t_cost, m_cost, lanes, threads, type,
       encoded_only, raw_only);

    return ARGON2_OK;
}

