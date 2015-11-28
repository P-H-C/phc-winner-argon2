from ctypes import *
import imp

import sys

IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)
_argon2 = cdll.LoadLibrary("./libargon2.so")

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


class Argon2Exception(Exception):
    pass


def _ensure_bytes(data):
    if IS_PY2 and isinstance(data, unicode):
        raise TypeError('can not encrypt/decrypt unicode objects')

    if not IS_PY2 and isinstance(data, str):
        return bytes(data, 'utf-8')

    return data


def hash(password, salt, t=16 , r=8, p=1, buflen=128, encodedlen=108):
    outbuf = create_string_buffer(buflen)
    encoded = create_string_buffer(encodedlen)

    password = _ensure_bytes(password)
    salt = _ensure_bytes(salt)

    result = _crypto_argon2(t, r, p,
                            password, len(password),
                            salt, len(salt),
                            outbuf, buflen,
                            encoded, encodedlen,
                            1)
    print result
    if result:
        raise Argon2Exception('could not compute hash')

    print len(outbuf.raw)
    return outbuf.raw
"""
int argon2_hash(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism,
                const void *pwd, const size_t pwdlen,
                const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen,
                char *encoded, const size_t encodedlen,
                argon2_type type)
"""