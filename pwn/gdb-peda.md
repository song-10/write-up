# PEDA

## 介绍

Python Exploit Development Assistance for GDB

## 安装与使用

### 安装使用

- `git clone https://github.com/longld/peda.git ~/peda`
- `echo "source ~/peda/peda.py" >> ~/.gdbinit`

### 指令

完整的指令列表：`peda help`
调试指令：

指令|功能
:--|:--:
`file 路径`|附加文件
`r`或`run`|开始执行
`c`或`continue`|继续执行
`step`|单步步入
`next`|单步步过
`b *addr`|在`addr`处下断
`enable`|激活断点
`disable`|禁用断点
`info b`|查看断点
`del num`|删除断点
`x/wx $esp`|以4字节16进制显示栈中内容
`stack 100`|显示栈中100项
`find xxx`|快速查找

指令说明

指令|说明
:--|:--:
`s`|按字符串输出
`x`|按十六进制格式显示变量
`d`|按十进制格式显示变量
`u`|按十六进制格式显示无符号整型
`o`|按八进制格式显示变量
`t`|按二进制格式显示变量
`a`|按十六进制格式显示变量
`c`|按字符格式显示变量
`f`|按浮点数格式显示变量

- `x/<n/f/u><addr>`
n,f,u为可选参数;b表示单字节,h表示双字节,w表示四字节,g表示八字节

指令|说明
:--|:--:
`x/s addr`|查看addr处的字符串
`x/wx addr`|十六进制形式查看addr处的一个双字
`x/c addr`|单字节查看addr处的字符
`x/16x $esp+12`|查看寄存器偏移
  
`set args`|指定运行时的参数(如:`set args 10 20 30 40 50`)

`show args`|查看设置好的运行参数

### 主要特征

`https://github.com/longld/peda    readme.md`

增强gdb的显示：在调试过程中着色并显示反汇编代码，寄存器，内存信息
添加命令以支持调试和漏洞利用开发

指令|说明
:--|:--:
`aslr`|显示/设置GDB的ASLR设置
`checksec`|检查二进制文件的各种安全选项
`dumpargs`|在调用指令停止时显示传递给函数的参数
`dumprop`|转储特定内存范围内的所有ROP小工具
`elfheader`|从调试的ELF文件中获取标头信息
`elfsymbol`|从ELF文件中获取非调试符号信息
`lookup`|搜索所有地址/对属于存储范围的地址的引用
`patch`|修补程序存储器从具有string / hexstring / int的地址开始
`pattern`|生成，搜索或将循环模式写入内存
`procinfo`|显示来自/ proc / pid /的各种信息
`pshow`|显示各种PEDA选项和其他设置
`pset`|设置各种PEDA选项和其他设置
`readelf`|从ELF文件获取标题信息
`ropgadget`|获取二进制或库的常见ROP小工具
`ropsearch`|搜索内存中的ROP小工具
`searchmem|find`|在内存中搜索模式；支持正则表达式搜索
`shellcode`|生成或下载常见的shellcode。
`skeleton`|生成python漏洞利用代码模板
`vmmap`|在调试过程中获取节的虚拟映射地址范围
`xormem`|将存储区与键异或
