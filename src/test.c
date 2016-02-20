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
             "894af4ff2e2d26f3ce15f77a7e1c25db45b4e20439e9961772ba199caddb001e",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$iUr0/"
             "y4tJvPOFfd6fhwl20W04gQ56ZYXcroZnK3bAB4");
    hashtest(2, 20, 1, "password",
             "58d4d929aeeafa40cc049f032035784fb085e8e0d0c5a51ea067341a93d6d286",
             "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$WNTZKa7q+"
             "kDMBJ8DIDV4T7CF6ODQxaUeoGc0GpPW0oY");
    hashtest(2, 18, 1, "password",
             "55292398cce8fc78685e610d004ca9bda5c325a0a2e6285a0de5f816df139aa6",
             "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$VSkjmMzo/"
             "HhoXmENAEypvaXDJaCi5ihaDeX4Ft8TmqY");
    hashtest(2, 8, 1, "password",
             "e346b1e1aa7ca58c9bb862e223ba5604064398d4394e49e90972c6b54cef43ed",
             "$argon2i$m=256,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$"
             "40ax4ap8pYybuGLiI7pWBAZDmNQ5TknpCXLGtUzvQ+0");
    hashtest(2, 8, 2, "password",
             "524179ce5cc9608228bddd4c2b78e394efa3fb0068703390abbd8afb1fa86368",
             "$argon2i$m=256,t=2,p=2$c29tZXNhbHQAAAAAAAAAAA$"
             "UkF5zlzJYIIovd1MK3jjlO+j+wBocDOQq72K+x+oY2g");
    hashtest(1, 16, 1, "password",
             "b49199e4ecb0f6659e6947f945e391c940b17106e1d0b0a9888006c7f87a789b",
             "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$"
             "tJGZ5Oyw9mWeaUf5ReORyUCxcQbh0LCpiIAGx/h6eJs");
    hashtest(4, 16, 1, "password",
             "72207b3312d79995fbe7b30664837ae1246f9a98e07eac34835ca3498e705f85",
             "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQAAAAAAAAAAA$"
             "ciB7MxLXmZX757MGZIN64SRvmpjgfqw0g1yjSY5wX4U");
    hashtest(2, 16, 1, "differentpassword",
             "8e286f605ed7383987a4aac25a28a04808593b6e17613bc31457146c4f3f4361",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$"
             "jihvYF7XODmHpKrCWiigSAhZO24XYTvDFFcUbE8/Q2E");
    memcpy(salt, "diffsalt", 8);
    hashtest(2, 16, 1, "password",
             "8f65b47d902fb2aee5e0b2bdc9041b249fc11f06f35551e0bee52716b41e8311",
             "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQAAAAAAAAAAA$"
             "j2W0fZAvsq7l4LK9yQQbJJ/BHwbzVVHgvuUnFrQegxE");

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
    assert(strcmp(msg, "Decoding failed") == 0);
    printf("Decode an error message: PASS\n");

    return 0;
}
