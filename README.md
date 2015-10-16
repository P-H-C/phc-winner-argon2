**WORK IN PROGRESS, DO NOT USE**

# Argon2

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net). 

You should use Argon2 whenever you need to hash passwords for credential
storage, key derivation, or other applications.

Argon2 is a family of functions... *(TODO, see which ones to keep)*

Please report bugs as issues on this repository (after searching if
anyone has already reported it).

## Usage

`make` builds the executable `argon2` and the shared library
`libargon2.so` (or `libargon2.dylib` on OSX):

`argon2` is a commmand-line utility to test specific Argon2 instances
  on your system...

Example use of libargon2...

## Intellectual property

Argon2 code is copyright (c) Daniel Dinu and Dmitry Khovratovich, 2014,
and under CC0 license.

BLAKE2 code is copyright (c) Samuel Neves, 2013-2015, and under CC0
license.

[`blake2/brg-endian.h`](src/blake2/brg-endian.h) is copyright (c) Brian
Gladman, 1998-2008, and under permissive license defined in the file
header.

