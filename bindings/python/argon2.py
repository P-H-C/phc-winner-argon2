#!/usr/bin/env python

from ctypes import cdll, c_uint32, c_char_p, c_size_t, c_int, create_string_buffer
import os
import platform
import sys


SYSTEM_TYPE = platform.system()
IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)
LOCAL_LIB_PATH = "../../"

if SYSTEM_TYPE == "Linux":
    LIB_NAME = "libargon2.so"
elif SYSTEM_TYPE == "Windows":
    LIB_NAME = "libargon2.dll"
elif SYSTEM_TYPE == "Darwin":
    LIB_NAME = "libargon2.dylib"
else:
    raise OSError("Your OS is not fully supported, you may try to modify code manually")

try:
    GLOBAL_LIB_PATH = os.environ['LD_LIBRARY_PATH']
    _argon2 = cdll.LoadLibrary(GLOBAL_LIB_PATH + LIB_NAME)
except (OSError, KeyError) as e:
    try:
        _argon2 = cdll.LoadLibrary(LOCAL_LIB_PATH + LIB_NAME)
    except OSError as e:
        raise OSError("You haven't installed Argon2 lib")

_crypto_argon2 = _argon2.argon2_hash
_crypto_argon2.argtypes = [
    c_uint32,  # uint32_t       N
    c_uint32,  # uint32_t       r
    c_uint32,  # uint32_t       p

    c_char_p,  # const uint8_t *passwd
    c_size_t,  # size_t         passwdlen

    c_char_p,  # const uint8_t *salt
    c_size_t,  # size_t         saltlen

    c_char_p,  # uint8_t       *buf
    c_size_t,  # size_t         buflen

    c_char_p,  # uint8_t       *encoded
    c_size_t,  # size_t         encodedlen

    c_uint32,  # uint32_t       Argon_type
]
_crypto_argon2.restype = c_int


class Argon2Type(object):
    Argon2_d = 0
    Argon2_i = 1


class Argon2Exception(Exception):
    errors = ("ARGON2_OK", "ARGON2_OUTPUT_PTR_NULL", "ARGON2_OUTPUT_TOO_SHORT", "ARGON2_OUTPUT_TOO_LONG",
              "ARGON2_PWD_TOO_SHORT", "ARGON2_PWD_TOO_LONG", "ARGON2_SALT_TOO_SHORT",
              "ARGON2_SALT_TOO_LONG", "ARGON2_AD_TOO_SHORT", "ARGON2_AD_TOO_LONG",
              "ARGON2_SECRET_TOO_SHORT", "ARGON2_SECRET_TOO_LONG",
              "ARGON2_TIME_TOO_SMALL", "ARGON2_TIME_TOO_LARGE", "ARGON2_MEMORY_TOO_LITTLE",
              "ARGON2_MEMORY_TOO_MUCH", "ARGON2_LANES_TOO_FEW", "ARGON2_LANES_TOO_MANY",
              "ARGON2_PWD_PTR_MISMATCH", "ARGON2_SALT_PTR_MISMATCH", "ARGON2_SECRET_PTR_MISMATCH",
              "ARGON2_AD_PTR_MISMATCH", "ARGON2_MEMORY_ALLOCATION_ERROR", "ARGON2_FREE_MEMORY_CBK_NULL",
              "ARGON2_ALLOCATE_MEMORY_CBK_NULL", "ARGON2_INCORRECT_PARAMETER", "ARGON2_INCORRECT_TYPE",
              "ARGON2_OUT_PTR_MISMATCH", "ARGON2_THREADS_TOO_FEW", "ARGON2_THREADS_TOO_MANY",
              "ARGON2_MISSING_ARGS", "ARGON2_ENCODING_FAIL", "ARGON2_DECODING_FAIL")


def _ensure_bytes(data):
    if IS_PY2 and isinstance(data, unicode):
        raise TypeError('can not encrypt/decrypt unicode objects')

    if not IS_PY2 and isinstance(data, str):
        return bytes(data, 'utf-8')

    return data


def argon2_hash(password, salt, t=16, m=8, p=1, buflen=128, argon_type=Argon2Type.Argon2_i):
    outbuf = create_string_buffer(buflen)
    password = _ensure_bytes(password)
    salt = _ensure_bytes(salt)

    result = _crypto_argon2(t, m, p,
                            password, len(password),
                            salt, len(salt),
                            outbuf, buflen,
                            None, 0,
                            argon_type)

    if result:
        raise Argon2Exception(Argon2Exception.errors[result])

    return outbuf.raw


if __name__ == "__main__":
    print(argon2_hash("password", "some salt"))
