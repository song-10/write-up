# 堆溢出

堆溢出是指程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数（之所以是可使用而不是用户申请的字节数，是因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数），因而导致了数据溢出，并覆盖到物理相邻的高地址的下一个堆块。
堆溢出漏洞发生的基本前提是

- 程序向堆上写入数据。
- 写入的数据大小没有被良好地控制。

堆溢出漏洞轻则可以使得程序崩溃，重则可以使得攻击者控制程序执行流程。
堆溢出是一种特定的缓冲区溢出（还有栈溢出， bss 段溢出等)。但是其与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此一般无法直接通过堆溢出来控制 EIP

## 利用堆溢出的策略

1. 覆盖与其物理相邻的下一个 chunk 的内容。

   - prev_size
   - size，主要有三个比特位，以及该堆块真正的大小。
     - NON_MAIN_ARENA
     - IS_MAPPED
     - PREV_INUSE
     - the True chunk size
   - chunk content，从而改变程序固有的执行流。

2. 利用堆中的机制（如 unlink 等 ）来实现任意地址写入（ Write-Anything-Anywhere）或控制堆块中的内容等效果，从而来控制程序的执行流。

## 堆溢出步骤

### 寻找堆分配函数

通常来说堆是通过调用 glibc 函数 malloc 进行分配的，在某些情况下会使用 calloc 分配。calloc 与 malloc 的区别是 calloc 在分配后会自动进行清空，这对于某些信息泄露漏洞的利用来说是致命的

```c
calloc(0x20);
//等同于
ptr=malloc(0x20);
memset(ptr,0,0x20);
```

还有一种分配是经由 realloc 进行的，realloc 函数可以身兼 malloc 和 free 两个函数的功能

```c++
#include <stdio.h>

int main(void)
{
  char *chunk,*chunk1;
  chunk=malloc(16);
  chunk1=realloc(chunk,32);
  return 0;
}
```

realloc 的操作并不是像字面意义上那么简单，其内部会根据不同的情况进行不同操作:

- 当 realloc(ptr,size) 的 size 不等于 ptr 的 size 时
  - 如果申请 size > 原来 size
    - 如果 chunk 与 top chunk 相邻，直接扩展这个 chunk 到新 size 大小
    - 如果 chunk 与 top chunk 不相邻，相当于 free(ptr),malloc(new_size)
  - 如果申请 size < 原来 size
    - 如果相差不足以容得下一个最小 chunk(64 位下 32 个字节，32 位下 16 个字节)，则保持不变
    - 如果相差可以容得下一个最小 chunk，则切割原 chunk 为两部分，free 掉后一部分
- 当 realloc(ptr,size) 的 size 等于 0 时，相当于 free(ptr)
- 当 realloc(ptr,size) 的 size 等于 ptr 的 size，不进行任何操作

### 寻找危险函数

常见危险函数

函数|描述
:--:|:--:
gets|直接读取一行，忽略 '\x00'
scanf|输入
vscanf|输入
sprintf|输出
strcpy|字符串复制，遇到 '\x00' 停止
strcat|字符串拼接，遇到 '\x00' 停止
bcopy|字符串

### 确定填充长度

计算**开始写入的地址与所要覆盖的地址之间的距离**，一个常见的误区是 malloc 的参数等于实际分配堆块的大小，但是事实上 ptmalloc 分配出来的大小是对齐的。这个长度一般是字长的 2 倍，比如 32 位系统是 8 个字节，64 位系统是 16 个字节。但是对于不大于 2 倍字长的请求，malloc 会直接返回 2 倍字长的块也就是最小 chunk，比如 64 位系统执行malloc(0)会返回用户区域为 16 字节的块。

```c++
#include <stdio.h>

int main(void)
{
  char *chunk;
  chunk=malloc(0);
  puts("Get input:");
  gets(chunk);
  return 0;
}
```

```s
//根据系统的位数，malloc会分配8或16字节的用户空间
0x602000:   0x0000000000000000  0x0000000000000021
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1
0x602030:   0x0000000000000000  0x0000000000000000
```

注意用户区域的大小不等于 chunk_hear.size，chunk_hear.size = 用户区域大小 + 2 * 字长

```c++
#include <stdio.h>

int main(void)
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}
```

用户申请的内存大小会被修改，其有可能会使用与其物理相邻的下一个 chunk 的 prev_size 字段储存内容。程序申请的 chunk 大小是 24 个字节。但是我们将其编译为 64 位可执行程序时，实际上分配的内存会是 16 个字节而不是 24 个。

```s
0x602000:   0x0000000000000000  0x0000000000000021
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1
```

用户申请的内存大小与 glibc 中实际分配的内存大小之间的转换

```c++
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)(
    ((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)
        ? MINSIZE
        : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK)
        & ~MALLOC_ALIGN_MASK
        )
```

16字节的空间通过使用下一个块的 pre_size 域来存取 24 字节的内容，当 req=24 时，request2size(24)=32。而除去 chunk 头部的 16 个字节。实际上用户可用 chunk 的字节数为 16。而 chunk 的 pre_size 仅当它的前一块处于释放状态时才起作用。所以用户这时候其实还可以使用下一个 chunk 的 prev_size 字段，正好 24 个字节。实际上 ptmalloc 分配内存是以双字为基本单位，以 64 位系统为例，分配出来的空间是 16 的整数倍，即用户申请的 chunk 都是 16 字节对齐的。
