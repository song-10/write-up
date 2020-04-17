# 调试时指定glibc

[原文链接](https://www.jianshu.com/p/1a966b62b3d4)

## 下载对应版本并编译 glibc

### 下载并解压

```s
wget https://ftp.gnu.org/gnu/glibc/glibc-2.25.tar.gz
tar xvf glibc-2.25.tar.gz
cd glibc-2.25
```

### 选择带 debug symbol 以及配置安装位置

```s
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -w" CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -w" ../Desktop/glibc-2.25/configure --prefix=/home/nop/lib/glibc-2.25/64
```

其中，

- CFLAGS、CXXFLAGS 与 debug symobl 有关
- `--prefix` 是安装目录

报错：

```s
configure: error:
*** These critical programs are missing or too old: gawk
*** Check the INSTALL file for required versions.
```

解决：

```s
sudo apt-get install gawk
```

### 编译和安装

```s
make && make install
```

## 使用相应版本

### 安装 patchelf

```s
git clone https://github.com/NixOS/patchelf.git
cd patchelf
./bootstrap.sh
./configure
make
sudo make install
```

改变dl位置：

```s
patchelf --set-interpreter /home/nop/lib/glibc-2.25/64/lib/ld-2.25.so test
```

查看结果：

```s
nop@nop-pwn:~/Desktop$ ldd test
    linux-vdso.so.1 =>  (0x00007ffceb7c0000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd2f0a21000)
    /home/nop/lib/glibc-2.25/64/lib/ld-2.25.so => /lib64/ld-linux-x86-64.so.2 (0x00007fd2f0deb000)
```
