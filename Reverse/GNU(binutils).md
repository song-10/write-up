# GNU binutils

## 简介

GNU binutils 是一个二进制工具集，默认情况下所有 Linux 发行版中都会安装这些二进制工具。

## 工具集

### readelf

显示ELF文件信息，`-h`选项可以将文件的ELF标题转储到屏幕上。
`readelf` 命令可提供有关二进制文件的大量信息。比如程序的位数（32或64）、程序在什么架构上执行(X86-64（Intel/AMD）架构)、该二进制文件的入口点是地址 0x400430(源程序的mian函数)。
使用选项`-x`将指定节转储存到屏幕上：

```shell
    readelf -x .rodata test.out
```

### size

列出节的大小和全部大小。
'size' 命令仅适用于目标文件和可执行文件，因此，如果尝试在简单的 ASCII 文件上运行它，则会抛出错误，提示“文件格式无法识别”。

### strings

打印文件中的可打印字符串。
在'strings'命令中添加'-d'标志以仅显示'.data'节中的可打印字符通常很有用。

### objdump

显示目标文件信息。
使用 -d 选项，可从二进制文件中反汇编出所有汇编指令。
使用命令查看指定函数的汇编指令：

```shell
objdump -d test.out | grep -A 9 main\>
```

### strip

从目标文件中剥离符号。
通过file命令可以查看文件是否二进制文件符号被剥离。
该命令通常用于在将二进制文件交付给客户之前减小二进制文件的大小，由于重要信息已从二进制文件中删除。因此它会妨碍调试，但是这个二进制文件可以完美地执行。
命令：

```shel
    file test.out       // 查看文件是否已经剥离符号
    du -b test.out      // 查看文件大小(字节数)
```

### addr2line

转换地址到文件名和行号。
`addr2line` 工具可以在二进制文件中查找地址，并将其与 C 源代码程序中的行进行匹配。

```shell
    gcc -g test.c       // 编译时需加上-g选项(调试信息)
    objdump -d test.out | grep -A 2 -E 'main>:|function1>:|function2>:'        // 通过grep过滤出所需的特定行
    addr2line -e test.out 40051d    // 使用addr2line命令显示40051d处对应c源码的位置
```

### nm

列出目标文件的符号。

```shell
    nm test.out | grep -Ei 'function|main|globalvar'    // 通过grep过滤出相关函数和变量信息
```

其中，函数被标记为T，它表示`.text`节中的符号，而变量标记为D，表示初始化的`.data`节中的符号。

[gnu-binutils](https://opensource.com/article/19/10/gnu-binutils)
