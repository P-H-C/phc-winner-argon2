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
#ifdef _MSC_VER
#include <intrin.h>
#endif

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /*4 MB*/
#define LANES_DEF 4
#define THREADS_DEF 4
#define SALTLEN_DEF 16

#define UNUSED_PARAMETER(x) (void)(x)

static __inline uint64_t rdtsc(void) {
#ifdef _MSC_VER
    return __rdtsc();
#else
#if defined(__amd64__) || defined(__x86_64__)
    uint64_t rax, rdx;
    __asm__ __volatile__("rdtsc" : "=a"(rax), "=d"(rdx) : :);
    return (rdx << 32) | rax;
#elif defined(__i386__) || defined(__i386) || defined(__X86__)
    uint64_t rax;
    __asm__ __volatile__("rdtsc" : "=A"(rax) : :);
    return rax;
#else
#error "Not implemented!"
#endif
#endif
}

/*
 * Custom allocate memory
 */
int CustomAllocateMemory(uint8_t **memory, size_t length) {
    *memory = (uint8_t *)malloc(length);

    if (!*memory) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}

/*
 * Custom free memory
 */
void CustomFreeMemory(uint8_t *memory, size_t length) {
    UNUSED_PARAMETER(length);

    if (memory) {
        free(memory);
    }
}

void usage(const char *cmd) {
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
    printf("\t-m m_cost\tMemory usage of 2^t_cost kibibytes, default %d\n",
           LOG_M_COST_DEF);
    printf("\t-p N\t\tParallelism, default %d\n", THREADS_DEF);
}

void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

void print_bytes(const void *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", ((const unsigned char *)s)[i] & 0xff);
    }

    printf("\n");
}

/*
 * Benchmarks Argon2 with salt length 16, password length 16, t_cost 1,
   and different m_cost and threads
 */
void benchmark() {
#define BENCH_OUTLEN 16
#define BENCH_INLEN 16
    const uint32_t inlen = BENCH_INLEN;
    const unsigned outlen = BENCH_OUTLEN;
    unsigned char out[BENCH_OUTLEN];
    unsigned char pwd_array[BENCH_INLEN];
    unsigned char salt_array[BENCH_INLEN];
#undef BENCH_INLEN
#undef BENCH_OUTLEN

    uint32_t t_cost = 1;

    memset(pwd_array, 0, inlen);
    memset(salt_array, 1, inlen);
    uint32_t thread_test[6] = {1, 2, 4, 6, 8, 16};

    uint32_t m_cost;

    for (m_cost = (uint32_t)1 << 10; m_cost <= (uint32_t)1 << 22; m_cost *= 2) {
        for (uint32_t i = 0; i < 6; ++i) {
            uint32_t thread_n = thread_test[i];
            uint64_t start_cycles, stop_cycles, stop_cycles_i;

            clock_t start_time = clock();
            start_cycles = rdtsc();

            Argon2_Context context = {
                out,  outlen, pwd_array, inlen,  salt_array, inlen,    NULL,
                0,    NULL,   0,         t_cost, m_cost,     thread_n, thread_n,
                NULL, NULL,   false,     false,  false,      false};
            argon2d(&context);
            stop_cycles = rdtsc();
            argon2i(&context);
            stop_cycles_i = rdtsc();
            clock_t stop_time = clock();

            uint64_t delta_d = (stop_cycles - start_cycles) / (m_cost);
            uint64_t delta_i = (stop_cycles_i - stop_cycles) / (m_cost);
            float mcycles_d = (float)(stop_cycles - start_cycles) / (1 << 20);
            float mcycles_i = (float)(stop_cycles_i - stop_cycles) / (1 << 20);
            printf(
                "Argon2d %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f "
                "Mcycles \n",
                t_cost, m_cost >> 10, thread_n, (float)delta_d / 1024,
                mcycles_d);
            printf(
                "Argon2i %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f "
                "Mcycles \n",
                t_cost, m_cost >> 10, thread_n, (float)delta_i / 1024,
                mcycles_i);

            float run_time = ((float)stop_time - start_time) / (CLOCKS_PER_SEC);
            printf("%2.4f seconds\n\n", run_time);
        }
    }
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
void run(uint8_t *out, char *pwd, uint8_t *salt, uint32_t t_cost,
         uint32_t m_cost, uint32_t lanes, uint32_t threads, const char *type) {
    uint64_t start_cycles, stop_cycles;
    clock_t start_time, stop_time;

    start_time = clock();
    start_cycles = rdtsc();

    /*Fixed parameters*/
    const unsigned out_length = 32;
    const unsigned salt_length = SALTLEN_DEF;
    unsigned pwd_length; 
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = true;

    if (!pwd)
        fatal("password missing");
    if (!salt) {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("salt missing");
    }

    pwd_length = strlen(pwd);

    UNUSED_PARAMETER(threads);

    Argon2_Context context = {
        out,          out_length, (uint8_t*)pwd,   pwd_length, salt,           salt_length,
        NULL,         0,          NULL, 0,         t_cost,         m_cost,
        lanes,        lanes,      NULL, NULL,      clear_password, clear_secret,
        clear_memory, false};

    if (!strcmp(type, "d"))
    {
        int result = argon2d(&context);
        printf("%s\n",error_message(result));
    }
    else if (!strcmp(type, "i"))
    {
        int result = argon2i(&context);
        printf("%s\n",error_message(result));
    }
    else {
        secure_wipe_memory(pwd, strlen(pwd));
        fatal("wrong Argon2 type");
    }

    stop_cycles = rdtsc();
    stop_time = clock();

    // show string encoding
    char encoded[300];
    encode_string(encoded, sizeof encoded, &context);
    printf("%s\n", encoded);

    // show running time/cycles
    float run_time = ((float)stop_time - start_time) / (CLOCKS_PER_SEC);
    float run_cycles = (float)(stop_cycles - start_cycles) / (1 << 20);
    printf("%2.3f seconds ", run_time);
    printf("(%.3f mebicycles)\n", run_cycles);
}

void generate_testvectors(const char *type) {
#define TEST_OUTLEN 32
#define TEST_PWDLEN 32
#define TEST_SALTLEN 16
#define TEST_SECRETLEN 8
#define TEST_ADLEN 12
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    bool print_internals = true;

    unsigned char out[TEST_OUTLEN];
    unsigned char pwd[TEST_PWDLEN];
    unsigned char salt[TEST_SALTLEN];
    unsigned char secret[TEST_SECRETLEN];
    unsigned char ad[TEST_ADLEN];
    const AllocateMemoryCallback myown_allocator = NULL;
    const FreeMemoryCallback myown_deallocator = NULL;

    unsigned t_cost = 3;
    unsigned m_cost = 16;
    unsigned lanes = 4;

    memset(pwd, 1, TEST_OUTLEN);
    memset(salt, 2, TEST_SALTLEN);
    memset(secret, 3, TEST_SECRETLEN);
    memset(ad, 4, TEST_ADLEN);

    printf("Generating test vectors for Argon2%s in file \"%s\".\n", type,
           ARGON2_KAT_FILENAME);

    Argon2_Context context = {out,
                              TEST_OUTLEN,
                              pwd,
                              TEST_PWDLEN,
                              salt,
                              TEST_SALTLEN,
                              secret,
                              TEST_SECRETLEN,
                              ad,
                              TEST_ADLEN,
                              t_cost,
                              m_cost,
                              lanes,
                              lanes,
                              myown_allocator,
                              myown_deallocator,
                              clear_password,
                              clear_secret,
                              clear_memory,
                              print_internals};
#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    if (!strcmp(type, "d")) {
        printf("Generating test vectors for Argon2d in file \"%s\".\n",
               ARGON2_KAT_FILENAME);
        argon2d(&context);
    } else if (!strcmp(type, "i")) {
        printf("Generating test vectors for Argon2i in file \"%s\".\n",
               ARGON2_KAT_FILENAME);
        argon2i(&context);
    } else
        fatal("wrong Argon2 type");
}

int main(int argc, char *argv[]) {
    unsigned char out[32];
    uint32_t m_cost = 1 << LOG_M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;
    char *pwd = NULL;
    uint8_t salt[SALTLEN_DEF];
    char *type = "i";

    remove(ARGON2_KAT_FILENAME);

#ifdef BENCH
    benchmark();
    return ARGON2_OK;
#endif
#ifdef GENKAT
    if (argc > 1) {
        type = argv[1];
    }
    generate_testvectors(type);
    return ARGON2_OK;
#endif

    if (argc < 3) {
        usage(argv[0]);
        return ARGON2_MISSING_ARGS;
    }

    // get password and salt from command line
    pwd = argv[1];
    if (strlen(argv[2]) > SALTLEN_DEF)
        fatal("salt too long");
    memset(salt, 0x00, SALTLEN_DEF); // pad with null bytes
    memcpy(salt, (uint8_t *)argv[2], strlen(argv[2]));

    // parse options
    for (int i = 3; i < argc; i++) {
        char *a = argv[i];

        if (!strcmp(a, "-m")) {
            if (i < argc - 1) {
                i++;
                m_cost = (uint8_t)1 << ((uint8_t)atoi(argv[i]) % 22);               
                continue;
            } else
                fatal("missing -m argument");
        } else if (!strcmp(a, "-t")) {
            if (i < argc - 1) {
                i++;
                t_cost = atoi(argv[i]) & 0xffffff;
                continue;
            } else
                fatal("missing -t argument");
        } else if (!strcmp(a, "-p")) {
            if (i < argc - 1) {
                i++;
                threads = atoi(argv[i]) % ARGON2_MAX_THREADS;
                lanes = threads;
                continue;
            } else
                fatal("missing -p argument");
        } else if (!strcmp(a, "-y")) {
            if (i < argc - 1) {
                i++;
                type = argv[i];
                continue;
            } else
                fatal("missing type argument");
        } else
            fatal("unknown argument");
    }
    printf("Memory blocks requested:  %"PRIu32" \n",m_cost);
    printf("Iterations requested:  %"PRIu32" \n",t_cost);
    printf("Lanes and threads requested:  %"PRIu32" \n",lanes);
    printf("Type requested: %c\n",type[0]);
    run(out, pwd, salt, t_cost, m_cost, lanes, threads, type);

    return ARGON2_OK;
}
