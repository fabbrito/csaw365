#!/usr/bin/env python

import string
import hashlib


def repeat(s, l):
    return (s * (int(l / len(s)) + 1))[:l]


def xor(x, key, offset=0):
    return ''.join(chr(ord(char) ^ ord(key[(offset + i) % len(key)])) for i, char in enumerate(x))


def guess_key_length(cipher, key_prefix):
    resp = []
    for i in range(len(cipher) - len(key_prefix) - 32):
        key = key_prefix + '\x00' * i
        decrypted = xor(cipher, key)

        hex_check = ''
        for j in range(len(cipher) - 32, len(cipher)):
            if (j % len(key)) < len(key_prefix):
                hex_check += decrypted[j]

        if (len(hex_check) > 1) and all(c in string.hexdigits for c in hex_check):
            resp.append(len(key))
    return resp


def decrypt(cipher, plain_prefix, key_prefix, key_len):
    schar = '~'
    plaintext = plain_prefix + schar * (len(cipher) - len(plain_prefix) -
                                        key_len - 32) + key_prefix + schar * (key_len - len(key_prefix)) + schar * 32
    plain = [c for c in plaintext]
    while schar in plaintext:
        plaintext = ''.join(plain)
        key = plaintext[-32 - key_len:-32]
        decrypted = xor(cipher, key)
        for i, c in enumerate(plaintext):
            if (c == schar) and (key[i % key_len] != schar):
                plain[i] = decrypted[i]
        if len(key.replace(schar, '')) == key_len:
            break
    return xor(cipher, key)


def main():
    secret = 'the_key_@10'
    plaintext = 'flag{__JUST_TESTING_THIS_SH*T__}' + secret
    plaintext += hashlib.md5(plaintext).hexdigest()

    cipher = xor(plaintext, secret).encode('hex')
    print cipher

    plain_prefix = 'flag{'
    key_prefix = xor(cipher.decode('hex')[:len(plain_prefix)], plain_prefix)

    possible_key_len = guess_key_length(cipher.decode('hex'), key_prefix)
    print possible_key_len

    print decrypt(cipher.decode('hex'), plain_prefix,
            key_prefix, possible_key_len[0])
    return


if __name__ == '__main__':
    main()
