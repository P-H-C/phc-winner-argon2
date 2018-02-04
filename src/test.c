/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "argon2.h"

#define OUT_LEN 32
#define ENCODED_LEN 108

/* Test harness will assert:
 * argon2_hash() returns ARGON2_OK
 * HEX output matches expected
 * encoded output matches expected
 * argon2_verify() correctly verifies value
 */

void hashtest(uint32_t version, uint32_t t, uint32_t m, uint32_t p, char *pwd,
              char *salt, char *hexref, char *mcfref) {
    unsigned char out[OUT_LEN];
    unsigned char hex_out[OUT_LEN * 2 + 4];
    char encoded[ENCODED_LEN];
    int ret, i;

    printf("Hash test: $v=%d t=%d, m=%d, p=%d, pass=%s, salt=%s: ", version,
           t, m, p, pwd, salt);

    ret = argon2_hash(t, 1 << m, p, pwd, strlen(pwd), salt, strlen(salt), out,
                      OUT_LEN, encoded, ENCODED_LEN, Argon2_i, version);
    assert(ret == ARGON2_OK);

    for (i = 0; i < OUT_LEN; ++i)
        sprintf((char *)(hex_out + i * 2), "%02x", out[i]);

    assert(memcmp(hex_out, hexref, OUT_LEN * 2) == 0);

    if (ARGON2_VERSION_NUMBER == version) {
        assert(memcmp(encoded, mcfref, strlen(mcfref)) == 0);
    }

    ret = argon2_verify(encoded, pwd, strlen(pwd), Argon2_i);
    assert(ret == ARGON2_OK);
    ret = argon2_verify(mcfref, pwd, strlen(pwd), Argon2_i);
    assert(ret == ARGON2_OK);

    printf("PASS\n");
}

int main() {
    int ret;
    unsigned char out[OUT_LEN];
    char const *msg;
    int version;

    version = ARGON2_VERSION_NUMBER;
    printf("Test Argon2i version number: %02x\n", version);

    /* Multiple test cases for various input values */
    hashtest(version, 2, 16, 1, "password", "somesalt",
             "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
             "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
#ifdef TEST_LARGE_RAM
    hashtest(version, 2, 20, 1, "password", "somesalt",
             "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
             "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ"
             "$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E");
#endif
    hashtest(version, 2, 18, 1, "password", "somesalt",
             "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
             "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ"
             "$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s");
    hashtest(version, 2, 8, 1, "password", "somesalt",
             "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
             "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ"
             "$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
    hashtest(version, 2, 8, 2, "password", "somesalt",
             "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
             "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ"
             "$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");
    hashtest(version, 1, 16, 1, "password", "somesalt",
             "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
             "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ"
             "$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");
    hashtest(version, 4, 16, 1, "password", "somesalt",
             "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
             "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ"
             "$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls");
    hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
             "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
             "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4");
    hashtest(version, 2, 16, 1, "password", "diffsalt",
             "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
             "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ"
             "$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE");

    /* Error state tests */

    /* Handle an invalid encoding correctly (it is missing a $) */
    ret = argon2_verify("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ"
                        "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
                        "password", strlen("password"), Argon2_i);
    assert(ret == ARGON2_DECODING_FAIL);
    printf("Recognise an invalid encoding: PASS\n");

    /* Handle an invalid encoding correctly (it is missing a $) */
    ret = argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
                        "wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
                        "password", strlen("password"), Argon2_i);
    assert(ret == ARGON2_DECODING_FAIL);
    printf("Recognise an invalid encoding: PASS\n");

    /* Handle an invalid encoding correctly (salt is too short) */
    ret = argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$"
                        "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
                        "password", strlen("password"), Argon2_i);
    assert(ret == ARGON2_SALT_TOO_SHORT);
    printf("Recognise an invalid salt in encoding: PASS\n");

    /* Handle an mismatching hash (the encoded password is "passwore") */
    ret = argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
                        "$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
                        "password", strlen("password"), Argon2_i);
    assert(ret == ARGON2_VERIFY_MISMATCH);
    printf("Verify with mismatched password: PASS\n");

    msg = argon2_error_message(ARGON2_DECODING_FAIL);
    assert(strcmp(msg, "Decoding failed") == 0);
    printf("Decode an error message: PASS\n");

    /* Common error state tests */

    printf("\n");
    printf("Common error state tests\n");

    ret = argon2_hash(2, 1, 1, "password", strlen("password"),
                      "diffsalt", strlen("diffsalt"),
                      out, OUT_LEN, NULL, 0, Argon2_i, version);
    assert(ret == ARGON2_MEMORY_TOO_LITTLE);
    printf("Fail on invalid memory: PASS\n");

    ret = argon2_hash(2, 1 << 12, 1, NULL, strlen("password"),
                      "diffsalt", strlen("diffsalt"),
                      out, OUT_LEN, NULL, 0, Argon2_i, version);
    assert(ret == ARGON2_PWD_PTR_MISMATCH);
    printf("Fail on invalid null pointer: PASS\n");

    ret = argon2_hash(2, 1 << 12, 1, "password", strlen("password"), "s", 1,
                      out, OUT_LEN, NULL, 0, Argon2_i, version);
    assert(ret == ARGON2_SALT_TOO_SHORT);
    printf("Fail on salt too short: PASS\n");

    return 0;
}
