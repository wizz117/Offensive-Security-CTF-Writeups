from pwn import *
r = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1272)
r.sendlineafter(b'abc123): ', b'vc2499')
r.recvuntil(b"Send me the right data")

# Send packets
r.send(bytes([0x03, 0x00, 0x00]))
print(r.recvline().decode())  

r.send(bytes([0x04, 0x01, 0x00, 0x37]))
print(r.recvline().decode()) 

r.send(bytes([0x03, 0x02, 0x00]))
print(r.recvline().decode()) 

print(r.recv().decode().strip())
r.close()

