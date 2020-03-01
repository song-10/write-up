# C语言入门

## Hello World

```c
    #include <stdio.h> //标准输入输出库
    #include <stdlib.h> //标准lib，包括system等函数

    int main(void)  //主函数声明格式
    {

        //双斜杠（//）单行注释
        // /*+内容+*/，多行注释
        printf("Hello,World");  //打印字符串

        system("pause");    //暂停程序，好观察结果
        return 0;   //程序结束
    }
```

## 数据类型

### 整型

```c
    #include <stdio.h>
    #include <stdlib.h>

    int main(void)
    {
        int a;  //声明一个整型，默认为有符号类型即signed，4 bytes
        printf("%d",a); //十进制形式输出有符号整数


        unsigned int b; //声明一个无符号整型，4 bytes
        printf("%u",b); //十进制形式输出无符号整数


        short int c;   //声明一个短整型，默认为有符号类型， 2 bytes
        printf("%hd",c);    //十进制输出短整型


        long int d;     //声明一个长整型，默认为有符号类型， 8 bytes
        printf("%ld",d);    //十进制输出长整型


        long long int e;    //声明长长整型，默认为有符号， 16 bytes，c99之后的拓展
        printf("%lld",e);   //十进制输出长长整型

        printf("%p",&a); //以十六进制输出变量a的地址，不带前缀0x
        printf("%#p",&a);   //以十六进制输出变量a的地址，带前缀0x
    }
```

>scanf获取输入

```c
    #include <stdio.h>
    #include <stdlib.h>

    int main(void)
    {
        int a;
        int b;

        scanf("%d",&a);     //获取输入赋值给a，输入以回车（换行）为结束符

        scanf("%d%d",&a,&b);    //同时获取多个输入时，输入用空格隔开

        scanf("%d,%d",&a,&b);   //同时获取多个输入时可以以逗号或者其他字符隔开，即转义字符中间用什么隔开，输入的时候就用什么隔开
        system("pause");
        return 0;
    }
```

> 忽略warning
> 方案一：文件首行添加宏定义： `#define _CRT_SECURE_NO_DEPRECATE`
> 方案二：添加：`#pragma warning(disable:4996)`

```c
    #define _CRT_SECURE_NO_DEPRECATE

    #include <stdio.h>
    #include <stdlib.h>

    #pragma warning(disable:4996)
    //4996为warning的“编号”

    int main(void)
    {
        system("pause");
        return 0;
    }
```
