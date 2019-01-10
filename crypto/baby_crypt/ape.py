#!/usr/bin/env python

from pwn import *
import string


def parse_blocks(x, n):
    blocks = []
    for i in range(len(x) / n):
        blocks.append(x[i * n:(i + 1) * n])
    return blocks


def pwn_conn(payload):
    
    sh.sendlineafter('): ', payload)
    data = sh.recvall()
    sh.close()
    return parse_blocks(data[:-1], 32)


def padit(message):
    if len(message) % 16 != 0:
        message = message + '0' * (16 - len(message) % 16)
    return message


def main():
    context.log_level = 'critical'
    sh = remote('10.67.0.1 ', 30277)
    leak_len = 40
    guessed_secret = 'flag{Crypt0_is_s0_h@rd_t0_d0...' # flag{Crypt0_is_s0_h@rd_t0_d0...}

    for i in range(len(guessed_secret), leak_len):
        payload = bytearray('0' * 15 + guessed_secret)
        payload.append('?')
        for guess in string.printable:
            payload[-1] = guess
            pfix = 16 - i % 16
            data = bytearray(payload[-16:] + '0' * (pfix - 1))
            sh.sendlineafter(': ', data)
            resp = sh.recvuntil('\n')
            cookie_str = 'Your Cookie is: '
            trim_resp = resp[resp.find(cookie_str) + len(cookie_str):-1]
            c_blocks = parse_blocks(trim_resp, 32)
            chosen_block = c_blocks[0]
            tail = "".join(c_blocks[1:])
            print "> {0} --- {1} --- {2} --- {3}".format(data, chosen_block, (chosen_block in tail), guessed_secret)
            if chosen_block in tail:
                guessed_secret += guess
                break
        if guessed_secret == '':
            print '########### ERROR ###########'
            return
        if guessed_secret[-1] == '}':
            break
    print "All guessed bytes: " + guessed_secret
    sh.close()
    return

if __name__ == "__main__":
    main()
