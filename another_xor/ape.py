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
    cipher = '274c10121a0100495b502d551c557f0b'\
        '0833585d1b27030b5228040d3753490a'\
        '1c025415051525455118001911534a00'\
        '52560a14594f0b1e490a010c4514411e'\
        '070014615a181b02521b580305170002'\
        '074b0a1a4c414d1f1d171d00151b1d0f'\
        '480e491e0249010c150050115c505850'\
        '434203421354424c1150430b5e094d14'\
        '4957080d4444254643'

    plain_prefix = 'flag{'
    key_prefix = xor(cipher.decode('hex')[:len(plain_prefix)], plain_prefix)

    possible_key_len = guess_key_length(cipher.decode('hex'), key_prefix)
    print possible_key_len

    print decrypt(cipher.decode('hex'), plain_prefix,
            key_prefix, possible_key_len[0])
    return


if __name__ == '__main__':
    main()



    # ciphermd5 = enc_text[-64:]
    # ciphertext = enc_text[:-64]

    # print len(ciphertext)

    # start_plain = 'flag{'
    # key_prefix = xor(ciphertext.decode('hex')[:len(start_plain)], start_plain)
