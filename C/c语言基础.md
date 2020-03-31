# C语言入门

## Hello World

```c++
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

```c++
    #include <stdio.h>
    #include <stdlib.h>

    int main(void)
    {
        int a;  // 声明一个整型，默认为有符号类型即signed，4 bytes
        printf("%d",a); // 十进制形式输出有符号整数


        unsigned int b; // 声明一个无符号整型，4 bytes
        printf("%u",b); // 十进制形式输出无符号整数


        short int c;   // 声明一个短整型，默认为有符号类型， 2 bytes
        printf("%hd",c);    // 十进制输出短整型


        long int d;     // 声明一个长整型，默认为有符号类型， 8 bytes
        printf("%ld",d);    // 十进制输出长整型


        long long int e;    // 声明长长整型，默认为有符号， 16 bytes，c99之后的拓展
        printf("%lld",e);   // 十进制输出长长整型

        printf("%p",&a); // 以十六进制输出变量a的地址，不带前缀0x
        printf("%#p",&a);   // 以十六进制输出变量a的地址，带前缀0x
    }
```

>scanf获取输入

```c++
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

```c++
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

## for循环

```c++
for(;;) // 死循环
for(i = 0;i < 10;i++)
/*
执行过程，
1. i = 0为初始值设置，在进入for循环时执行一次
2. i<10,为状态检测，每一轮循环开始都会执行这一部分
3. i++，状态更新，循环体内容执行结束之后执行这部分内容，更新for循环状态
*/
```

## 逗号表达式

```c++
for(i = 1, cost = N; i <= 16 ; i++, cost += 20)
    printf("test for code 'for;\n");
```

逗号的性质：

1. 保证了被他分隔的表达式从左往右求值（换言之，逗号是一个序列点，所以逗号左侧项的所有副作用都在程序执行逗号右侧之前发生）

    ```c++
    ounces++, cost = ounces*20;
    // 先递增ounces，然后在第二个表达式中使用ounces的新值，然后赋值给cost
    ```

2. 整个逗号表达式的值是右侧项的值

    ```c++
    x = (y = 3, (z = ++y + 2) + 5);
    // 先把3赋给y，递增y为4，然后把4+2之和赋给z，最后加上5，然后把结果赋给x
    x = 249,500;
    // 等价于 x = 249; 500; 其中，500为一个表达式（do nothing）
    x = (249,500);
    // (249,500) 的值为500，然后赋给x
    ```

## 数组

1. 出于速度原因，编译器不会对数组做越界检测，这样导致的问题是修改或读取程序其他数据，可能会破环程序结果甚至导致程序异常中断。

2. 如果char类型的数组结尾包含了一个表示字符串末尾的空字符 '\0'，则该数组中的内容就构成了一个字符串。

3. 数组由相邻的内存位置构成，只储存相同类型的数据。

## 逻辑运算

c99 新增了可替代逻辑运算符的拼写，被定义在 ios646.h中

传统写法|ios646.h
:--:|:--:
&&|and
`||`|or
!|not

## ctype.h 中的字符测试函数

函数名|返回为真的参数情况
:--:|:--:
isalnum()|字母或数字
isalpha()|字母
isblank()|标准空白字符（空格、水平制表符或换行符）或任何其他本地化指定为空白的字符
iscntrl()|控制字符，如ctrl+B
isdigit()|数字
isgraph()|除空格之外的任意可打印字符
islower()|小写字母
isprint()|可打印字符
ispunct()|标点符号（除空格或字母数字字符意外的任何可打印字符）
isspace()|空白字符（空格、换行符、换页符、回车符、垂直制表符、水平制表符或其他本地化定义的字符）
isupper()|大写字母
isxdigit()|十六进制数字字符

函数名|行为
:--:|:--:
tolower()|如果参数是大写字符，返回参数的小写字母，否则返回原始参数
toupper()|如果参数是小写字母，返回参数的大写字母，否则返回原始参数
