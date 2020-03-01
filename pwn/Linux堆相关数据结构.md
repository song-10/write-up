# 堆相关数据结构

## 堆概述

在程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。堆其实就是程序虚拟地址空间的一块连续的线性区域，它由低地址向高地址方向增长。
堆管理器用于管理堆，它处于用户程序和内核之间：

1. 响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。同时，为了保持内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与操作系统进行交互。
2. 管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给操作系统的，而是由堆管理器进行管理。这些释放的内存可以来响应用户新申请的内存的请求。

Linux 中早期的堆分配与回收由 Doug Lea 实现，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。Wolfram Gloger 在 Doug Lea 的基础上进行改进使其可以支持多线程，这个堆分配器就是 ptmalloc 。在 glibc-2.3.x. 之后，glibc 中集成了 ptmalloc2。
目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块。
需要注意的是，在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想，**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页面给用户使用。

## 堆操作的相关函数

### malloc

```c
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.
  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
```

malloc 函数返回对应大小字节的内存块的指针，函数针对一些异常情况的处理：

- 当 n=0 时，返回当前系统允许的堆的最小内存块。
- 当 n 为负数时，由于在大多数系统上，**size_t 是无符号数**，所以程序就会申请很大的内存空间，但通常来说都会失败，因为系统没有那么多的内存可以分配。

### free

```c
/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. It can have arbitrary (i.e., bad!)
  effects if p has already been freed.
  Unless disabled (using mallopt), freeing very large spaces will
  when possible, automatically trigger operations that give
  back unused memory to the system, thus reducing program footprint.
*/
```

free 函数会释放由 p 所指向的内存块。这个内存块有可能是通过 malloc 函数得到的，也有可能是通过相关的函数 realloc 得到的。
free 函数对异常情况的处理：

- **当 P 为空指针时，函数不执行任何操作**
- 当 p 已经被释放之后，再次释放会出现乱七八糟的效果，这其实就是 double free
- 除了被禁用 (mallopt) 的情况下，当释放很大的内存空间时，程序会将这些内存空间还给系统，以便于减小程序所使用的内存空间。

## 堆的数据结构

## 微观结构

### malloc_chunk

在程序的执行过程中，由 malloc 申请的内存称为 chunk 。这块内存在 ptmalloc 内部用 malloc_chunk 结构体来表示。当程序申请的 chunk 被 free 后，会被加入到相应的空闲管理列表中。无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构：

```c++
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

INTERNAL_SIZE_T，SIZE_SZ，MALLOC_ALIGN_MASK：

```c
/* INTERNAL_SIZE_T is the word-size used for internal bookkeeping of
   chunk sizes.
   The default version is the same as size_t.
   While not strictly necessary, it is best to define this as an
   unsigned type, even if size_t is a signed type. This may avoid some
   artificial size limitations on some systems.
   On a 64-bit machine, you may be able to reduce malloc overhead by
   defining INTERNAL_SIZE_T to be a 32 bit `unsigned int' at the
   expense of not being able to handle more than 2^32 of malloced
   space. If this limitation is acceptable, you are encouraged to set
   this unless you are on a platform requiring 16byte alignments. In
   this case the alignment requirements turn out to negate any
   potential advantages of decreasing size_t word size.
   Implementors: Beware of the possible combinations of:
     - INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,
       and might be the same width as int or as long
     - size_t might have different width and signedness as INTERNAL_SIZE_T
     - int and long might be 32 or 64 bits, and might be the same width
   To deal with this, most comparisons and difference computations
   among INTERNAL_SIZE_Ts should cast them to unsigned long, being
   aware of the fact that casting an unsigned int to a wider long does
   not sign-extend. (This also makes checking for negative numbers
   awkward.) Some of these casts result in harmless compiler warnings
   on some systems.  */
#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
```

一般来说，size_t 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数。

- **prev_size**，如果该 chunk 的物理相邻的前一地址 chunk（两个指针的地址差值为前一 chunk 大小，较低地址为前一地址）是空闲的话，那该字段记录的是前一个 chunk 的大小 (包括 chunk 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据
- **size**，该 chunk 的大小，大小必须是`2 * SIZE_SZ`的整数倍。如果申请的内存大小不是`2 * SIZE_SZ`的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响
- **fd,bk**，chunk 处于分配状态时，从 fd 字段开始是用户的数据。chunk 空闲时，会被添加到对应的空闲管理链表中,其中 fd 指向下一个（非物理相邻）的空闲的 chunk，而bk则指向上一个，通过 fd 和 bk 可以将空闲的 chunk 块加入到空闲的 chunk 块链表进行统一管理
- **fd_nextsize， bk_nextsize**，只有 chunk 空闲的时候才使用，用于 large chunk，其中 fd_nextsize 指向前一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针,bk_bextsize 则指向后一个。一般空闲的 large chunk 在 fd 的遍历顺序中，按照由大到小的顺序排列

一个已经分配的 chunk 的结构如下。称前两个字段称为 chunk header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。
当一个 chunk 处于使用状态时，它的下一个 chunk 的 prev_size 域无效，所以下一个 chunk 的该部分也可以被当前 chunk 使用。这就是 chunk 中的空间复用。

```s
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- chunk header
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P| <- chun header
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- user data
        |             User data starts here...                          .
        .                                                               .
        .             (malloc_usable_size() bytes)                      .
next    .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

被释放的 chunk 被记录在链表中（可能是循环双向链表，也可能是单向链表）

```s
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:` |             Size of chunk, in bytes                     |A|0|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Forward pointer to next chunk in list             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Back pointer to previous chunk in list            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
 next   .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`foot:` |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

一般情况下，物理相邻的两个空闲 chunk 会被合并为一个 chunk 。堆管理器会通过 prev_size 字段以及 size 字段合并两个物理相邻的空闲 chunk 块。

### chunk 相关宏

#### chunk 与 men 指针头部的转换

mem 指向用户得到的内存的起始位置

```c++
/* conversion from malloc headers to user pointers, and back */
#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))
```

#### 最小的 chunk 大小

```c
/* The smallest possible chunk */
#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))
```

offsetof 函数计算出 fd_nextsize 在 malloc_chunk 中的偏移，说明最小的 chunk 至少要包含 bk 指针

#### 最小堆内存大小

用户最小申请的内存大小必须是 2 * SIZE_SZ 的最小整数倍
就目前而看 MIN_CHUNK_SIZE 和 MINSIZE 大小是一致的

```c++
/* The smallest size we can malloc is an aligned minimal chunk */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define MINSIZE(unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
```

#### 检查分配给用户的内存是否对齐（2 * SIZE_SZ大小对齐）

```c++
/* Check if m has acceptable alignment */
// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) (uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) & MALLOC_ALIGN_MASK)
```

#### 请求字节数判断

```c++
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req) ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
```

#### 将用户请求内存大小转为实际分配内存大小

```c++
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req) (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE) ? MINSIZE : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
/*  Same, except also perform argument check */
#define checked_request2size(req, sz)
    if (REQUEST_OUT_OF_RANGE(req)) {
        __set_errno(ENOMEM);
        return 0;
    }
    (sz) = request2size(req);
```

当一个 chunk 处于已分配状态时，它的物理相邻的下一个 chunk 的 prev_size 字段必然是无效的，故而这个字段就可以被当前这个 chunk 使用。这就是 ptmalloc 中 chunk 间的复用。具体流程如下

1. 首先，利用 REQUEST_OUT_OF_RANGE 判断是否可以分配用户请求的字节大小的 chunk。
2. 其次，需要注意的是用户请求的字节是用来存储数据的，即 chunk header 后面的部分。与此同时，由于 chunk 间复用，所以可以使用下一个 chunk 的 prev_size 字段。因此，这里只需要再添加 SIZE_SZ 大小即可以完全存储内容。
3. 由于系统中所允许的申请的 chunk 最小是 MINSIZE，所以与其进行比较。如果不满足最低要求，那么就需要直接分配 MINSIZE 字节。
4. 如果大于的话，因为系统中申请的 chunk 需要 2 * SIZE_SZ 对齐，所以这里需要加上 MALLOC_ALIGN_MASK 以便于对齐。

#### 标记位

```c++
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)

/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)

/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)

/*
   Bits to mask off when extracting size
   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

#### 获取chunk size

```c++
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)
```

#### 获取下一个物理相邻的 chunk

```c++
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
```

#### 获取前一个 chunk 的信息

```c++
/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
```

#### 当前 chunk 使用状态相关操作

```c++
/* extract p's inuse bit */
#define inuse(p) ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)
```

#### 设置 chunk 的 size 字段

```c++
/* Set size at head, without disturbing its use bit */
// SIZE_BITS = 7
#define set_head_size(p, s) ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s) ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s) (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))
```

#### 获取指定偏移的 chunk

```c++
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```

#### 指定偏移处 chunk 使用状态相关操作

```c++
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s) (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s) (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s) (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))
```

### bin

用户释放掉的 chunk 不会马上归还给系统，ptmalloc 会统一管理 heap 和 mmap 映射区域中的空闲的 chunk。当用户再一次请求分配内存时，ptmalloc 分配器会试图在空闲的 chunk 中挑选一块合适的给用户。这样可以避免频繁的系统调用，降低内存分配的开销。

在具体的实现中，ptmalloc 采用分箱式方法对空闲的 chunk 进行管理:
根据空闲的 chunk 的大小以及使用状态将 chunk 初步分为 4 类：fast bins，small bins，large bins，unsorted bin。每类中仍然有更细的划分，相似大小的 chunk 会用双向链表链接起来。也就是说，在每类 bin 的内部仍然会有多个互不相关的链表来保存不同大小的 chunk。
对于 small bins，large bins，unsorted bin 来说，ptmalloc 将它们维护在同一个数组中。这些 bin 对应的数据结构在 malloc_state 中

```c
#define NBINS 128
/* Normal bins packed as described above */
mchunkptr bins[ NBINS * 2 - 2 ];
```

bin 的排布都会遵循一个原则：任意两个物理相邻的空闲 chunk 不能在一起
需要注意的是，并不是所有的 chunk 被释放后就立即被放到 bin 中。ptmalloc 为了提高分配的速度，会把一些小的 chunk 先放到 fast bins 的容器内。而且，fastbin 容器中的 chunk 的使用标记总是被置位的，所以不满足上面的原则。

bin 通用的宏

```c++
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) - offsetof(struct malloc_chunk, fd))

/* analog of ++bin */
//获取下一个bin的地址
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))

/* Reminders about list directionality within bins */
// 这两个宏可以用来遍历bin
// 获取 bin 的位于链表头的 chunk
#define first(b) ((b)->fd)
// 获取 bin 的位于链表尾的 chunk
#define last(b) ((b)->bk)
```

#### Fast bin

```c++
/*
   Fastbins
    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
typedef struct malloc_chunk *mfastbinptr;

/*
  This is in malloc_state.
  Fastbins */
mfastbinptr fastbinsY[ NFASTBINS ];
```

glibc 采用单向链表对其中的每个 bin 进行组织，并且每个 bin 采取 LIFO 策略，最近释放的 chunk 会更早地被分配 ，即当用户需要的 chunk 的大小小于 fastbin 的最大大小时， ptmalloc 会首先判断 fastbin 中相应的 bin 中是否有对应大小的空闲块，如果有的话，就会直接从这个 bin 中获取 chunk。如果没有的话，ptmalloc 才会做接下来的一系列操作。

默认情况下（32 位系统为例）， fastbin 中默认支持最大的 chunk 的数据空间大小为 64 字节。但是其可以支持的 chunk 的数据空间最大为 80 字节。除此之外， fastbin 最多可以支持的 bin 的个数为 10 个，从数据空间为 8 字节开始一直到 80 字节（注意这里说的是数据空间大小，也即除去 prev_size 和 size 字段部分的大小）定义如下

```c++
#define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST (64 * SIZE_SZ / 4)
#endif

/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE (80 * SIZE_SZ / 4)

/*
   Since the lowest 2 bits in max_fast don't matter in size comparisons,
   they are used as flags.
 */

/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.

   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */
//判断分配区是否有 fast bin chunk，1表示没有
#define FASTCHUNKS_BIT (1U)

#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */
// MORECORE是否返回连续的内存区域。
// 主分配区中的MORECORE其实为sbr()，默认返回连续虚拟地址空间
// 非主分配区使用mmap()分配大块虚拟内存，然后进行切分来模拟主分配区的行为
// 而默认情况下mmap映射区域是不保证虚拟地址空间连续的，所以非主分配区默认分配非连续虚拟地址空间。
#define NONCONTIGUOUS_BIT (2U)

#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */

#define ARENA_CORRUPTION_BIT (4U)

#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)

/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */

#define set_max_fast(s) global_max_fast = (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) &  ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast
```

ptmalloc 默认情况下会调用 set_max_fast(s) 将全局变量 global_max_fast 设置为 DEFAULT_MXFAST，也就是设置 fast bins 中 chunk 的最大值。当 MAX_FAST_SIZE 被设置为 0 时，系统就不会支持 fastbin

##### fastbin 的索引

```c++
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ])

/* offset 2 to use otherwise unindexable first 2 bins */
// chunk size=2*size_sz*(2+idx)
// 这里要减2，否则的话，前两个bin没有办法索引到。
#define fastbin_index(sz) ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

需要特别注意的是，fastbin 范围的 chunk 的 inuse 始终被置为 1。因此它们不会和其它被释放的 chunk 合并。
但是当释放的 chunk 与该 chunk 相邻的空闲 chunk 合并后的大小大于 FASTBIN_CONSOLIDATION_THRESHOLD 时，内存碎片可能比较多了，我们就需要把 fast bins 中的 chunk 都进行合并，以减少内存碎片对系统的影响。

```c++
/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */

#define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)
```

malloc_consolidate 函数可以将 fastbin 中所有能和其它 chunk 合并的 chunk 合并在一起

```c
/*
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
```

#### Small bin

small bins 中每个 chunk 的大小与其所在的 bin 的 index 的关系为：`chunk_size = 2 * SIZE_SZ *index`

下标|SIZE_SZ=4（32 位|SIZE_SZ=8（64 位）
:--:|:--:|:--:
2|16|32
3|24|48
4|32|64
5|40|80
x|`2*4*x`|`2*8*x`
63|504|1008

small bins 中一共有 62 个循环双向链表，每个链表中存储的 chunk 大小都一致。比如对于 32 位系统来说，下标 2 对应的双向链表中存储的 chunk 大小为均为 16 字节。每个链表都有链表头结点，这样可以方便对于链表内部结点的管理。此外，small bins 中每个 bin 对应的链表采用 FIFO 的规则，所以同一个链表中先被释放的 chunk 会先被分配出去

```c++
#define NSMALLBINS 64
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT
// 是否需要对small bin的下标进行纠正
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)

#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
//判断chunk的大小是否在small bin范围内
#define in_smallbin_range(sz) ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
// 根据chunk的大小得到small bin对应的索引。
#define smallbin_index(sz) ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3)) + SMALLBIN_CORRECTION)
```

#### Large Bin

large bins 中一共包括 63 个 bin，每个 bin 中的 chunk 的大小不一致，而是处于一定区间范围内。此外，这 63 个 bin 被分成了 6 组，每组 bin 中的 chunk 大小之间的公差一致

组|数量|公差
:--:|:--:|:--:
1|2|64B
2|16|512B
3|8|4096B
4|4|32768B
5|2|262144B
6|1|不限制

以 32 位平台的 large bin 为例，第一个 large bin 的起始 chunk 大小为 512 字节，位于第一组，所以该 bin 可以存储的 chunk 的大小范围为 [512,512+64)

```c++
//32 位平台下，第一个 large bin 的起始 chunk 大小为例，为 512 字节，那么 512>>6 = 8，所以其下标为 56+8=64
#define largebin_index_32(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 38)                                     \
         ? 56 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

#define largebin_index_32_big(sz)                                              \
    (((((unsigned long) (sz)) >> 6) <= 45)                                     \
         ? 49 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 48)                                     \
         ? 48 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)

#define largebin_index(sz) (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big(sz) : largebin_index_32(sz))
```

#### Unsorted Bin

unsorted bin 可以视为空闲 chunk 回归其所属 bin 之前的缓冲区

```c++
/*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

 /* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M) (bin_at(M, 1))
```

unsorted bin 处于 bin 数组下标 1 处。故而 unsorted bin 只有一个链表。unsorted bin 中的空闲 chunk 处于乱序状态，主要有两个来源

1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中

Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO

#### 根据 chunk 的大小统一地获得 chunk 所在的索引

```c++
#define bin_index(sz) ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))
```

### Top Chunk

```c
/*
   Top

    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M) (unsorted_chunks(M))
```

程序第一次进行 malloc 的时候，heap 会被分为两块，一块给用户，剩下的那块就是 top chunk。
所谓的 top chunk 就是处于当前堆的物理地址最高的 chunk。这个 chunk 不属于任何一个 bin，它的作用在于当所有的 bin 都无法满足用户请求的大小时，如果其大小不小于指定的大小，就进行分配，并将剩下的部分作为新的 top chunk。否则，就对 heap 进行扩展后再进行分配。在 main arena 中通过 sbrk 扩展 heap，而在 thread arena 中通过 mmap 分配新的 heap。
需要注意的是，top chunk 的 prev_inuse 比特位始终为 1，否则其前面的 chunk 就会被合并到 top chunk 中。
初始情况下，可以将 unsorted chunk 作为 top chunk。

### last remainder

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 chunk 可能并不和申请的内存大小一致，这时候就将分割之后的剩余部分称之为 last remainder chunk ，unsort bin 也会存这一块。top chunk 分割剩下的部分不会作为 last remainder.

## 宏观结构

### arena

#### arena数量

```s
For 32 bit systems:
     Number of arena = 2 * number of cores.
For 64 bit systems:
     Number of arena = 8 * number of cores.
```

#### arena 分配规则

假设有如下情境：一台只含有一个处理器核心的PC机安装有32位操作系统，其上运行了一个多线程应用程序，共含有4个线程——主线程和三个用户线程。显然线程个数大于系统能维护的最大arena个数（2*核心数 + 1= 3）那么此时glibc malloc就需要确保这4个线程能够正确地共享这3个arena

当主线程首次调用malloc的时候，glibc malloc会直接为它分配一个main arena，而不需要任何附加条件。
当用户线程1和用户线程2首次调用malloc的时候，glibc malloc会分别为每个用户线程创建一个新的thread arena，此时，各个线程与arena是一一对应的。
当用户线程3调用malloc的时候，glibc malloc 能维护的arena个数已经达到上限，无法再为线程3分配新的arena，那么就需要重复使用已经分配好的3个arena中的一个(main arena, arena 1或者arena 2)。

1. glibc malloc循环遍历所有可用的arenas，在遍历的过程中，它会尝试lock该arena。如果成功lock(该arena当前对应的线程并未使用堆内存则表示可lock)则该arena被线程3共享使用。

2. 如果没能找到可用的arena，那么就将线程3的malloc操作阻塞，直到有可用的arena为止。

3. 如果线程3再次调用malloc的话，glibc malloc就会先尝试使用最近访问的arena。如果这个arena可用的话，就直接使用，否则就将线程3阻塞，直到这个 arena再次可用为止。

#### heap_info

heap_info 用于记录线程申请内存时的数据结构（程序刚开始执行时，每个线程是没有 heap 区域的），该数据结构是专门为从 Memory Mapping Segment 处申请的内存准备的，即为非主线程准备的。

主线程可以通过 sbrk() 函数扩展 program break location 获得（直到触及 Memory Mapping Segment），只有一个 heap，没有 heap_info 数据结构

```c++
#define HEAP_MIN_SIZE (32 * 1024)
#ifndef HEAP_MAX_SIZE
# ifdef DEFAULT_MMAP_THRESHOLD_MAX
#  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
# else
#  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
# endif
#endif

/* HEAP_MIN_SIZE and HEAP_MAX_SIZE limit the size of mmap()ed heaps
   that are dynamically created for multi-threaded programs.  The
   maximum size must be a power of two, for fast determination of
   which heap belongs to a chunk.  It should be much larger than the
   mmap threshold, so that requests with a size just below that
   threshold can be fulfilled without creating too many heaps.  */

/***************************************************************************/

/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected  PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

主要描述堆的基本信息

- 堆对应的 arena 的地址
- 由于一个线程申请一个堆之后，可能会使用完，之后就必须得再次申请。因此，一个线程可能会有多个堆。prev 即记录了上一个 heap_info 的地址。这里可以看到每个堆的 heap_info 是通过单向链表进行链接的。
- size 表示当前堆的大小
- 最后一部分确保对齐

#### malloc_state

该结构用于管理堆，记录每个 arena 当前申请的内存的具体状态，比如说是否有空闲 chunk，有什么大小的空闲 chunk 等。
无论是 thread arena 还是 main arena，它们都只有一个 malloc state 结构。由于 thread 的 arena 可能有多个，malloc state 结构会在最新申请的 arena 中。
main arena 的 malloc_state 并不是 heap segment 的一部分，而是一个全局变量，存储在 libc.so 的数据段

```c++
struct malloc_state {
    /* Serialize access.  */
    __libc_lock_define(, mutex);

    /* Flags (formerly in max_fast).  */
    int flags;

    /* Fastbins */
    mfastbinptr fastbinsY[ NFASTBINS ];

    /* Base of the topmost chunk -- not otherwise kept in a bin */
    mchunkptr top;

    /* The remainder from the most recent split of a small request */
    mchunkptr last_remainder;

    /* Normal bins packed as described above */
    mchunkptr bins[ NBINS * 2 - 2 ];

    /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/
    unsigned int binmap[ BINMAPSIZE ];

    /* Linked list, points to the next arena */
    struct malloc_state *next;

    /* Linked list for free arenas.  Access to this field is serialized
       by free_list_lock in arena.c.  */
    struct malloc_state *next_free;

    /* Number of threads attached to this arena.  0 if the arena is on
       the free list.  Access to this field is serialized by
       free_list_lock in arena.c.  */
    INTERNAL_SIZE_T attached_threads;

    /* Memory allocated from the system in this arena.  */
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
};
```

- `__libc_lock_define(, mutex);` :该变量用于控制程序串行访问同一个分配区，当一个线程获取了分配区之后，其它线程要想访问该分配区，就必须等待该线程分配完成后才能够使用。
- `flags` :flags 记录了分配区的一些标志，比如 bit0 记录了分配区是否有 fast bin chunk ，bit1 标识分配区是否能返回连续的虚拟地址空间

```c++
/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.
   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */

#define FASTCHUNKS_BIT (1U)

#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.
   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */

#define NONCONTIGUOUS_BIT (2U)

#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */

#define ARENA_CORRUPTION_BIT (4U)

#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)
```

- `fastbinsY[NFASTBINS]` :存放每个 fast chunk 链表头部的指针
- `top` :指向分配区的 top chunk
- `last_reminder` :最新的 chunk 分割之后剩下的那部分
- `bins` :用于存储 unstored bin，small bins 和 large bins 的 chunk 链表。
- `binmap` :ptmalloc 用一个 bit 来标识某一个 bin 中是否包含空闲 chunk 。
