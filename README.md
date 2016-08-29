# Argon2

[![Build Status](https://travis-ci.org/P-H-C/phc-winner-argon2.svg?branch=master)](https://travis-ci.org/P-H-C/phc-winner-argon2)
[![Build status](https://ci.appveyor.com/api/projects/status/8nfwuwq55sgfkele?svg=true)](https://ci.appveyor.com/project/P-H-C/phc-winner-argon2)
[![codecov.io](https://codecov.io/github/P-H-C/phc-winner-argon2/coverage.svg?branch=master)](https://codecov.io/github/P-H-C/phc-winner-argon2?branch=master)

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net).

Argon2 is a password-hashing function that summarizes the state of the
art in the design of memory-hard functions and can be used to hash
passwords for credential storage, key derivation, or other applications.

It has a simple design aimed at the highest memory filling rate and
effective use of multiple computing units, while still providing defense
against tradeoff attacks (by exploiting the cache and memory organization
of the recent processors).

Argon2 has two variants: Argon2d and Argon2i. Argon2d is faster and
uses data-depending memory access, which makes it highly resistant
against GPU cracking attacks and suitable for applications with no threats
from side-channel timing attacks (eg. cryptocurrencies). Argon2i instead
uses data-independent memory access, which is preferred for password
hashing and password-based key derivation, but it is slower as it makes
more passes over the memory to protect from tradeoff attacks.

Argon2i and Argon2d are parametrized by:

* A **time** cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
* A **memory** cost, which defines the memory usage, given in kibibytes
* A **parallelism** degree, which defines the number of parallel threads

The [Argon2 document](argon2-specs.pdf) gives detailed specs and design
rationale.

Please report bugs as issues on this repository.

## Usage

`make` builds the executable `argon2`, the static library `libargon2.a`,
and the shared library `libargon2.so` (or `libargon2.dylib` on OSX).
Make sure to run `make test` to verify that your build produces valid
results.

### Command-line utility

`argon2` is a command-line utility to test specific Argon2 instances
on your system. To show usage instructions, run
`./argon2 -h` as
```
Usage:  ./argon2 [-h] salt [-d] [-t iterations] [-m memory] [-p parallelism] [-l hash length] [-e|-r]
        Password is read from stdin
Parameters:
        salt            The salt to use, at least 8 characters 
        -d              Use Argon2d instead of Argon2i (which is the default)
        -t N            Sets the number of iterations to N (default = 3)
        -m N            Sets the memory usage of 2^N KiB (default 12)
        -p N            Sets parallelism to N threads (default 1)
        -l N            Sets hash output length to N bytes (default 32)
        -e              Output only encoded hash
        -r              Output only the raw bytes of the hash
        -h              Print argon2 usage
```
For example, to hash "password" using "somesalt" as a salt and doing 2
iterations, consuming 64 MiB, using four parallel threads and an output hash
of 24 bytes
```
$ echo -n "password" | ./argon2 somesalt -t 2 -m 16 -p 4 -l 24
Type:           Argon2i
Iterations:     2
Memory:         65536 KiB
Parallelism:    4
Hash:           45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
Encoded:        $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.188 seconds
Verification ok
```

### Library

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

The example program below hashes the string "password" with Argon2i
using the high-level API and then using the low-level API. While the
high-level API only takes input/output buffers and the two cost
parameters, the low-level API additionally takes parallelism parameters
and several others, as defined in [`include/argon2.h`](include/argon2.h).


Here the time cost `t_cost` is set to 2 iterations, the
memory cost `m_cost` is set to 2<sup>16</sup> kibibytes (64 mebibytes),
and parallelism is set to 1 (single-thread).

Compile for example as `gcc test.c libargon2.a -Isrc -o test`, if the program
below is named `test.c` and placed in the project's root directory.

```c
#include "argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"

int main(void)
{
    uint8_t hash1[HASHLEN];
    uint8_t hash2[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

    // low-level API
    argon2_context context = {
        hash2,  /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        pwdlen, /* password length */
        salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        ARGON2_DEFAULT_FLAGS /* by default the password is zeroed on exit */
    };

    int rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    free(pwd);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );
    if (memcmp(hash1, hash2, HASHLEN)) {
        for( int i=0; i<HASHLEN; ++i ) {
            printf( "%02x", hash2[i] );
        }
        printf("\nfail\n");
    }
    else printf("ok\n");
    return 0;
}
```

To use Argon2d instead of Argon2i call `argon2d_hash` instead of
`argon2i_hash` using the high-level API, and `argon2d` instead of
`argon2i` using the low-level API.

To produce the crypt-like encoding rather than the raw hash, call
`argon2i_hash_encoded` for Argon2i and `argon2d_hash_encoded` for Argon2d.

See [`include/argon2.h`](include/argon2.h) for API details.

*Note: in this example the salt is set to the all-`0x00` string for the
sake of simplicity, but in your application you should use a random salt.*


### Benchmarks

`make bench` creates the executable `bench`, which measures the execution
time of various Argon2 instances:

```
$ ./bench
Argon2d 1 iterations  1 MiB 1 threads:  5.91 cpb 5.91 Mcycles
Argon2i 1 iterations  1 MiB 1 threads:  4.64 cpb 4.64 Mcycles
0.0041 seconds

Argon2d 1 iterations  1 MiB 2 threads:  2.76 cpb 2.76 Mcycles
Argon2i 1 iterations  1 MiB 2 threads:  2.87 cpb 2.87 Mcycles
0.0038 seconds

Argon2d 1 iterations  1 MiB 4 threads:  3.25 cpb 3.25 Mcycles
Argon2i 1 iterations  1 MiB 4 threads:  3.57 cpb 3.57 Mcycles
0.0048 seconds

(...)

Argon2d 1 iterations  4096 MiB 2 threads:  2.15 cpb 8788.08 Mcycles
Argon2i 1 iterations  4096 MiB 2 threads:  2.15 cpb 8821.59 Mcycles
13.0112 seconds

Argon2d 1 iterations  4096 MiB 4 threads:  1.79 cpb 7343.72 Mcycles
Argon2i 1 iterations  4096 MiB 4 threads:  2.72 cpb 11124.86 Mcycles
19.3974 seconds

(...)
```

## Bindings

Bindings are available for the following languages (make sure to read
their documentation):

* [Go](https://github.com/tvdburgt/go-argon2) by [@tvdburgt](https://github.com/tvdburgt)
* [Haskell](https://hackage.haskell.org/package/argon2-1.0.0/docs/Crypto-Argon2.html) by [@ocharles](https://github.com/ocharles)
* [JavaScript (native)](https://github.com/ranisalt/node-argon2), by [@ranisalt](https://github.com/ranisalt)
* [JavaScript (ffi)](https://github.com/cjlarose/argon2-ffi), by [@cjlarose](https://github.com/cjlarose)
* [JavaScript (browser)](https://github.com/antelle/argon2-browser), by [@antelle](https://github.com/antelle)
* [JVM](https://github.com/phxql/argon2-jvm) by [@phXql](https://github.com/phxql)
* [Lua (native)](https://github.com/thibaultCha/lua-argon2) by [@thibaultCha](https://github.com/thibaultCha)
* [Lua (ffi)](https://github.com/thibaultCha/lua-argon2-ffi) by [@thibaultCha](https://github.com/thibaultCha)
* [OCaml](https://github.com/Khady/ocaml-argon2) by [@Khady](https://github.com/Khady)
* [Python (native)](https://pypi.python.org/pypi/argon2), by [@flamewow](https://github.com/flamewow)
* [Python (ffi)](https://pypi.python.org/pypi/argon2_cffi), by [@hynek](https://github.com/hynek)
* [Ruby](https://github.com/technion/ruby-argon2) by [@technion](https://github.com/technion)
* [Rust](https://github.com/quininer/argon2-rs) by [@quininer](https://github.com/quininer)
* [C#/.NET CoreCLR](https://github.com/kmaragon/Konscious.Security.Cryptography) by [@kmaragon](https://github.com/kmaragon)


## Test Suite

There are two sets of test suites. One is a low level test for the hash
function, the other tests the higher level API. Both of these are built and
executed by running:

`make test`

## Intellectual property

Except for the components listed below, the Argon2 code in this
repository is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and under
[CC0 license](https://creativecommons.org/about/cc0).

The string encoding routines in [`src/encoding.c`](src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under [CC0
license](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under [CC0
license](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
