from pwn import remote
from gmpy2 import iroot
import binascii

# Connect to the server
host, port = 'offsec-chalbroker.osiris.cyber.nyu.edu', 1515
connection = remote(host, port)

# Send NetID
connection.sendlineafter(b'abc123): ', b'vc2499')

# Function to safely parse 'key = value' lines
def get_value():
    while True:
        line = connection.recvline().strip()
        if b'=' in line:
            return int(line.split(b'=')[1])

# Retrieve the challenge parameters
public_exponent = get_value()  # e
modulus = get_value()          # n
ciphertext = get_value()       # c

# Step 1: Compute the 5th root of the ciphertext
plaintext, is_exact = iroot(ciphertext, public_exponent)

# Step 2: Convert the result to a readable flag
if is_exact:
    flag = binascii.unhexlify(hex(plaintext)[2:]).decode()
    print("Flag:", flag)
else:
    print("Failed to compute the exact root.")

# Close the connection
connection.close()

