from pwn import *

context.log_level = 'error'

for key in range(256):
    with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1254) as conn:
        conn.sendlines([b'vc2499', str(key).encode()])
        if b'flag' in (response := conn.recvall()):
            print(f"Correct key: {key}\nFlag: {response.decode()}")
            break
    print(f"Key {key} was incorrect.")
