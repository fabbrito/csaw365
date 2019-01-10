#!/usr/bin/env python

from pwn import *
import string


def parse_blocks(x, n):
    # Separate blocks of n chars
    return [x[i * n:(i + 1) * n] for i in range(len(x) / n)]


def main():
    context.log_level = 'critical'
    sh = remote('10.67.0.1 ', 30296)

    # Previous knowledge
    guessed_secret = ''  # flag{Crypt0_is_s0_h@rd_t0_d0...}
    
    # Leak next 40 bytes of data
    leak = 40
    for i in range(len(guessed_secret), leak):
        # Create known payload: 000...000? and iterate '?' over all printable chars
        payload = bytearray('0' * 15 + guessed_secret)
        payload.append('?')
        for guess in string.printable:
            payload[-1] = guess

            # Padding: created in order to leak chars from the flag
            # Crafting of the leaked block
            padding = 16 - i % 16
            data = bytearray(payload[-16:] + '0' * (padding - 1))
            sh.sendlineafter(': ', data)
            resp = sh.recvuntil('\n')

            # Split the server response and separate the AES-ECB blocks
            cookie_str = 'Your Cookie is: '
            trim_resp = resp[resp.find(cookie_str) + len(cookie_str):-1]
            c_blocks = parse_blocks(trim_resp, 32) # 16 chars --> 32 hex

            # Compares the payload block with the one with leaked chars
            payload_block = c_blocks[0]
            tail = "".join(c_blocks[1:])
            print "> {0} --- {1} --- {2} --- {3}".format(data, payload_block, (payload_block in tail), guessed_secret)
            
            # If TRUE, adds the guess to accumulated knowledge 
            if payload_block in tail:
                guessed_secret += guess
                break
        # Fail check
        if guessed_secret == '':
            print '########### ERROR ###########'
            return

        # Find the end of the flag
        if guessed_secret[-1] == '}':
            break

    # Result
    print "All guessed bytes: " + guessed_secret
    sh.close()
    return


if __name__ == "__main__":
    main()
