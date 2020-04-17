# House Of Orange

House of Orange 的利用比较特殊:

1. 目标漏洞是堆上的漏洞,但是不存在 free 函数或其他释放堆块的函数
2. 通过漏洞利用获得 free 的效果

## 原理

在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)，简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins

假设目前的 top chunk 已经不满足 malloc 的分配需求：

1. malloc调用会执行到 libc.so 的_int_malloc函数中，在_int_malloc函数中，会依次检验 fastbin、small bins、unsorted bin、large bins 是否可以满足分配要求，因为尺寸问题这些都不符合
2. _int_malloc函数会试图使用 top chunk，在这里 top chunk 也不能满足分配的要求，因此会执行如下分支

   ```c++
   /*
    Otherwise, relay to handle system-dependent cases
    */
    else {
        void *p = sysmalloc(nb, av);
        if (p != NULL && __builtin_expect (perturb_byte, 0))
            alloc_perturb (p, bytes);
        return p;
    }
    ```

3. 此时 ptmalloc 已经不能满足用户申请堆内存的操作，需要执行 sysmalloc 来向系统申请更多的空间,对于堆来说有 mmap 和 brk 两种分配方式，我们需要让堆以 brk 的形式拓展，之后原有的 top chunk 会被置于 unsorted bin 中

要实现 brk 拓展 top chunk 需要绕过一些 libc 中的 check:

1. malloc 的尺寸不能大于mmp_.mmap_threshold

   ```c++
   if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
   ```
