#ifndef ENCODING_H
#define ENCODING_H
#include "argon2.h"

#define ARGON2_MAX_DECODED_LANES UINT32_C(255)
#define ARGON2_MIN_DECODED_SALT_LEN UINT32_C(8)
#define ARGON2_MIN_DECODED_OUT_LEN UINT32_C(12)


/*
* encode an Argon2 hash string into the provided buffer. 'dst_len'
* contains the size, in characters, of the 'dst' buffer; if 'dst_len'
* is less than the number of required characters (including the
* terminating 0), then this function returns 0.
*
* if ctx->outlen is 0, then the hash string will be a salt string
* (no output). if ctx->saltlen is also 0, then the string will be a
* parameter-only string (no salt and no output).
*
* on success, 1 is returned.
*
* No other parameters are checked
*/
int encode_string(char *dst, size_t dst_len, argon2_context *ctx,
                  argon2_type type);


/*
* Decodes an Argon2 hash string into the provided structure 'ctx'.
* The fields ctx.saltlen, ctx.adlen, ctx.outlen set the maximal salt, ad, out length values 
* that are allowed; invalid input string causes an error
* Returned value is 1 on success, 0 on error.
*
* WARNING: the procedure rejects some inputs that are valid outputs of encode_string(), see below
* Allows m_cost and t_cost between 1 and 2^32-1 (hard-coded values), 
* parallelism between 1 and ARGON2_MAX_DECODED_LANES.
* Also rejects m_cost if smaller than  8 times parallelism.
* Rejects salts shorter than ARGON2_MIN_DECODED_SALT_LEN bytes.
* Rejects hashes shorter than ARGON2_MIN_DECODED_OUT_LEN bytes.
*/
int decode_string(argon2_context *ctx, const char *str, argon2_type type);

#endif
