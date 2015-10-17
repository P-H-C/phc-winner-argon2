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

You'll find detailed specifications and design ratinoale in the [Argon2
document](argon2-specs.pdf).

Please report bugs as issues on this repository (after searching if
anyone has already reported it).

## Usage

`make` builds the executable `argon2` and the shared library
`libargon2.so` (or `libargon2.dylib` on OSX):

`argon2` is a commmand-line utility to test specific Argon2 instances
on your system and run benchmarks. To show instructions run `./argon2`
without arguments.

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

Below is an example of the high-level API, calling Argon2i with
`t_cost=2` (two passes) and `m_cost=50*( 1<<10 )` (50 times
2<sup>10</sup> kibibytes, or 50 mebibytes), as passed as parameters, and
the default parallelism of one lane and one thread.
```
todo...
```
The code below does the same using the low-level API:
```
todo...
```

To use Argon2d instead of Argon2i with the high-level API, call
`hashpwd2` instead of `hashpwd`.


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

