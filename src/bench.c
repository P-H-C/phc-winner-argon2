#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#include "argon2.h"

static uint64_t rdtsc(void) {
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
 * Benchmarks Argon2 with salt length 16, password length 16, t_cost 1,
   and different m_cost and threads
 */
static void benchmark() {
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
    uint32_t m_cost;
    uint32_t thread_test[6] = {1, 2, 4, 6, 8, 16};

    memset(pwd_array, 0, inlen);
    memset(salt_array, 1, inlen);

    for (m_cost = (uint32_t)1 << 10; m_cost <= (uint32_t)1 << 22; m_cost *= 2) {
        unsigned i;
        for (i = 0; i < 6; ++i) {
            argon2_context context;
            uint32_t thread_n = thread_test[i];
            uint64_t stop_cycles, stop_cycles_i;
            clock_t stop_time;
            uint64_t delta_d, delta_i;
            double mcycles_d, mcycles_i, run_time;

            clock_t start_time = clock();
            uint64_t start_cycles = rdtsc();

            context.out = out;
            context.outlen = outlen;
            context.pwd = pwd_array;
            context.pwdlen = inlen;
            context.salt = salt_array;
            context.saltlen = inlen;
            context.secret = NULL;
            context.secretlen = 0;
            context.ad = NULL;
            context.adlen = 0;
            context.t_cost = t_cost;
            context.m_cost = m_cost;
            context.lanes = thread_n;
            context.threads = thread_n;
            context.allocate_cbk = NULL;
            context.free_cbk = NULL;
            context.flags = 0;

            argon2d(&context);
            stop_cycles = rdtsc();
            argon2i(&context);
            stop_cycles_i = rdtsc();
            stop_time = clock();

            delta_d = (stop_cycles - start_cycles) / (m_cost);
            delta_i = (stop_cycles_i - stop_cycles) / (m_cost);
            mcycles_d = (double)(stop_cycles - start_cycles) / (1UL << 20);
            mcycles_i = (double)(stop_cycles_i - stop_cycles) / (1UL << 20);
            printf("Argon2d %d iterations  %d MiB %d threads:  %2.2f cpb %2.2f "
                   "Mcycles \n",
                   t_cost, m_cost >> 10, thread_n, (float)delta_d / 1024,
                   mcycles_d);
            printf("Argon2i %d iterations  %d MiB %d threads:  %2.2f cpb %2.2f "
                   "Mcycles \n",
                   t_cost, m_cost >> 10, thread_n, (float)delta_i / 1024,
                   mcycles_i);

            run_time = ((double)stop_time - start_time) / (CLOCKS_PER_SEC);
            printf("%2.4f seconds\n\n", run_time);
        }
    }
}

int main() {
    benchmark();
    return ARGON2_OK;
}
