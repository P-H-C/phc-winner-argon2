#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "argon2.h"

#define OUT_LEN 32
#define SALT_LEN 16
#define ENCODED_LEN 108

uint8_t salt[SALT_LEN];

/* Test harness will assert:
 * argon_hash2() returns ARGON2_OK
 * HEX output matches expected
 * encoded output matches expected
 * argon2_verify() correctly verifies value
 */

void hashtest(uint32_t t, uint32_t m, uint32_t p, char *pwd, char *hexref,
              char *mcfref) {
    unsigned char out[OUT_LEN];
    unsigned char hex_out[OUT_LEN * 2 + 4];
    char encoded[ENCODED_LEN];
    int ret, i;

    printf("Hash test: t=%d, m=%d, p=%d, pass=%s, salt=%s: ", t, m, p, pwd,
           salt);
    ret = argon2_hash(t, 1 << m, p, pwd, strlen(pwd), salt, SALT_LEN, out,
                      OUT_LEN, encoded, ENCODED_LEN, Argon2_i);
    assert(ret == ARGON2_OK);

    for (i = 0; i < OUT_LEN; ++i)
        sprintf((char *)(hex_out + i * 2), "%02x", out[i]);

    assert(memcmp(hex_out, hexref, OUT_LEN * 2) == 0);
    assert(memcmp(encoded, mcfref, strlen(mcfref)) == 0);
    ret = argon2_verify(encoded, pwd, strlen(pwd), Argon2_i);
    assert(ret == ARGON2_OK);
    printf("PASS\n");
}

int main() {
    int ret;
    unsigned char out[OUT_LEN];
    char const *msg;

    memset(salt, 0x00, SALT_LEN); /* pad with null bytes */
    memcpy(salt, "somesalt", 8);

    /* Multiple test cases for various input values */
    hashtest(2, 16, 1, "password",
             "1c7eeef9e0e969b3024722fc864a1ca9f6ca20da73f9bf3f1731881beae2039e",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$HH7u+eDpabMCRyL8hkocqfbKINpz+b8/FzGIG+riA54");
    hashtest(2, 20, 1, "password",
             "253068ce02908829f9c8a026dc7cf4bd4497fd781faa1665a0d0b10d699e0ebd",
             "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$JTBozgKQiCn5yKAm3Hz0vUSX/XgfqhZloNCxDWmeDr0");
    hashtest(2, 18, 1, "password",
             "5c6dfd2712110cf88f1426059b01d87f8210d5368da0e7ee68586e9d4af4954b",
             "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$XG39JxIRDPiPFCYFmwHYf4IQ1TaNoOfuaFhunUr0lUs");
    hashtest(2, 8, 1, "password",
             "dfebf9d4eadd6859f4cc6a9bb20043fd9da7e1e36bdacdbb05ca569f463269f8",
             "$argon2i$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$3+v51OrdaFn0zGqbsgBD/Z2n4eNr2s27BcpWn0Yyafg");
    hashtest(2, 8, 2, "password",
             "aea9db129d7f8c50d410a6599b0fb3d786a60ec16a3030b9ddd21ee7b6470f7f",
             "$argon2i$m=256,t=2,p=2$c29tZXNhbHQAAAAAAAAAAA"
             "$rqnbEp1/jFDUEKZZmw+z14amDsFqMDC53dIe57ZHD38");
    hashtest(1, 16, 1, "password",
             "fabd1ddbd86a101d326ac2abe79660202b10192925d2fd2483085df94df0c91a",
             "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo");
    hashtest(4, 16, 1, "password",
             "b3b4cb3d6e2c1cb1e7bffdb966ab3ceafae701d6b7789c3f1e6c6b22d82d99d5",
             "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$s7TLPW4sHLHnv/25Zqs86vrnAda3eJw/HmxrItgtmdU");
    hashtest(2, 16, 1, "differentpassword",
             "b2db9d7c0d1288951aec4b6e1cd3835ea29a7da2ac13e6f48554a26b127146f9",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA"
             "$studfA0SiJUa7EtuHNODXqKafaKsE+b0hVSiaxJxRvk");
    memcpy(salt, "diffsalt", 8);
    hashtest(2, 16, 1, "password",
             "bb6686865f2c1093f70f543c9535f807d5b42d5dc6d71f14a4a7a291913e05e0",
             "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQAAAAAAAAAAA"
             "$u2aGhl8sEJP3D1Q8lTX4B9W0LV3G1x8UpKeikZE+BeA");

    /* Error state tests */

    ret = argon2_hash(2, 1, 1, "password", strlen("password"), salt, SALT_LEN,
                      out, OUT_LEN, NULL, 0, Argon2_i);
    assert(ret == ARGON2_MEMORY_TOO_LITTLE);
    printf("Fail on invalid memory: PASS\n");

    ret = argon2_hash(2, 1 << 12, 1, NULL, strlen("password"), salt, SALT_LEN,
                      out, OUT_LEN, NULL, 0, Argon2_i);
    assert(ret == ARGON2_PWD_PTR_MISMATCH);
    printf("Fail on invalid null pointer: PASS\n");

    ret = argon2_hash(2, 1 << 12, 1, "password", strlen("password"), salt, 1,
                      out, OUT_LEN, NULL, 0, Argon2_i);
    assert(ret == ARGON2_SALT_TOO_SHORT);
    printf("Fail on salt too short: PASS\n");

    /* Handle an invalid encoding correctly (it is missing a $) */
    ret = argon2_verify("$argon2i$m=262144,t=2,p=1$"
                        "c29tZXNhbHQAAAAAAAAAAAVSkjmMzo/"
                        "HhoXmENAEypvaXDJaCi5ihaDeX4Ft8TmqY",
                        "password", strlen("password"), Argon2_i);
    assert(ret == ARGON2_DECODING_FAIL);
    printf("Recognise an invalid encoding: PASS\n");

    msg = argon2_error_message(ret);
    assert(strcmp(msg, "Decoding failed")==0);
    printf("Decode an error message: PASS\n");

    return 0;
}
