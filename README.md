**WORK IN PROGRESS, DO NOT USE**

# Argon2

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net). 

You should use Argon2 whenever you need to hash passwords for credential
storage, key derivation, or other applications.

There are two main versions of Argon2, *Argon2i* and *Argon2d*. Argon2i
is the safest against side-channel attacks, while Argon2d provides the
highest resistance against GPU cracking attacks.

Both Argon2i and Argon2d are parametrized by

* A **memory cost** (argument `m_cost`), given in kibibytes, which defines the memory usage of the function
* A **time cost** (argument `t_cost`), which defines the amount of computation
  realized and therefore the execution time
* The degree of parallelism, through the arguments
    - `lanes`, the number of parallel series of operations (possible
      parallelism)
    - `threads`, the number of threads allocated to the parallel
      execution (actual parallelism)

You'll find detailed specifications and design rationale in the [Argon2
document](argon2-specs.pdf).

Please report bugs as issues on this repository (after searching if
anyone has already reported it).

## Usage

`make` builds the executable `argon2` and the shared library
`libargon2.so` (or `libargon2.dylib` on OSX). Make sure to run `test.sh`
to verify that your build produces valid test vectors.

`argon2` is a commmand-line utility to test specific Argon2 instances
on your system and run benchmarks. To show instructions run `./argon2`
without arguments.

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

The example program below hashes "password" with Argon2i using the
high-level API and then using the low-level API. While the high-level
API only takes input/output buffers and the two cost parameters, the
low-level API additionally takes parallelism parameters and several
others, as defined in [`argon2.h`](src/argon2.h#L129).

Here `t_cost` is set to 2 passes, `m_cost` is set to 50 times
2<sup>10</sup> kibibytes (that is, 50 mebibytes), and there's no
parallelism (single-lane, single-thread).

```c
#include "argon2.h"
#include <stdio.h>
#include <string.h>

#define OUTLEN 32
#define SALTLEN 16
#define PWD "password"

int main()
{
    uint8_t out1[OUTLEN];
    uint8_t out2[OUTLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *in = (uint8_t *)strdup(PWD);
    uint32_t inlen = strlen((char *)in);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = 50*(1<<10);   // 50 mebibytes memory usage

    // high-level API
    hashpwd( out1, OUTLEN, in, inlen, salt, SALTLEN, t_cost, m_cost );

    // low-level API
    uint32_t lanes = 1;             // lanes 1 by default
    uint32_t threads = 1;           // threads 1 by default
    in = (uint8_t *)strdup(PWD);    // cos' erased by previous call
    Argon2_Context context = {out2, OUTLEN, in, inlen, salt, SALTLEN, \
        NULL, 0, NULL, 0, t_cost, m_cost, lanes, threads, NULL, NULL, \
        true, true, true, false };
    argon2i( &context );

    for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out1[i] ); printf( "\n" );
    if (memcmp(out1, out2, OUTLEN)) {
        for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out2[i] ); printf( "\n" );
        printf("fail\n");
    }
    else printf("ok\n");

    return 0;
}
```

To use Argon2d instead of Argon2i call `hashpwd2` instead of `hashpwd`
using the high-level API, and `argon2d` instead of `argon2i` using the
low-level API.


## Intellectual property

Argon2 code is copyright (c) 2015 Daniel Dinu and Dmitry Khovratovich,
with modifications copyright (c) 2015 Jean-Philippe Aumasson and Samuel
Neves. The Argon2 code is under [CC0
license](https://creativecommons.org/about/cc0).

BLAKE2 code is copyright (c) Samuel Neves, 2013-2015, and under [CC0
license](https://creativecommons.org/about/cc0).

[`blake2/brg-endian.h`](src/blake2/brg-endian.h) is copyright (c) Brian
Gladman, 1998-2008, and under permissive license defined in the file
header.

