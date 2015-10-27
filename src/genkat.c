#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argon2.h"

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

static void generate_testvectors(const char *type) {
#define TEST_OUTLEN 32
#define TEST_PWDLEN 32
#define TEST_SALTLEN 16
#define TEST_SECRETLEN 8
#define TEST_ADLEN 12
    argon2_context context;

    unsigned char out[TEST_OUTLEN];
    unsigned char pwd[TEST_PWDLEN];
    unsigned char salt[TEST_SALTLEN];
    unsigned char secret[TEST_SECRETLEN];
    unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 3;
    unsigned m_cost = 16;
    unsigned lanes = 4;

    memset(pwd, 1, TEST_OUTLEN);
    memset(salt, 2, TEST_SALTLEN);
    memset(secret, 3, TEST_SECRETLEN);
    memset(ad, 4, TEST_ADLEN);

    printf("Generating test vectors for Argon2%s in file \"%s\".\n", type,
           ARGON2_KAT_FILENAME);

    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.pwd = pwd;
    context.pwdlen = TEST_PWDLEN;
    context.salt = salt;
    context.saltlen = TEST_SALTLEN;
    context.secret = secret;
    context.secretlen = TEST_SECRETLEN;
    context.ad = ad;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = ARGON2_PRINT;

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
    const char * type = (argc > 1) ? argv[1] : "i";
    remove(ARGON2_KAT_FILENAME);
    generate_testvectors(type);
    return 0;
}