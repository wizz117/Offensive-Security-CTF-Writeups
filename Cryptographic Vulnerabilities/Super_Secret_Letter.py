from pwn import *
import ctypes, re, time

# Load libc for C's rand() and srand()
libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes, libc.rand.restype = [ctypes.c_uint], ctypes.c_int

# XOR decrypt with seed
def decrypt(ciphertext, seed):
    libc.srand(seed)
    return bytes(c ^ (libc.rand() & 0xFF) for c in ciphertext)

# Connect to server and extract ciphertext
p = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1517)
p.sendlineafter(b'abc123): ', b'vc2499')
response = p.recvall(timeout=2).decode()
ciphertext = bytes.fromhex(re.search(r'[a-fA-F0-9]{64,}', response).group(0))
p.close()

# Brute-force squared seeds
current_time = int(time.time())
for t in range(current_time - 3600, current_time + 3600):
    try:
        plaintext = decrypt(ciphertext, t * t).decode('utf-8')
        if "flag{" in plaintext:
            print(f"[+] Got the Flag!\nSeed: {t * t}\nPlaintext: {plaintext}")
            exit()
    except UnicodeDecodeError:
        continue

print("[-] Flag not found.")
