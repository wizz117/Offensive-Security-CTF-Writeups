from pwn import remote
from gmpy2 import gcdext, powmod, invert
import binascii

# Connect to the challenge server
host, port = 'offsec-chalbroker.osiris.cyber.nyu.edu', 1516
connection = remote(host, port)

# Send your NetID
connection.sendlineafter(b'abc123): ', b'vc2499')

# Function to parse 'key = value' lines safely
def get_value():
    while True:
        line = connection.recvline().strip()
        if b'=' in line:
            return int(line.split(b'=')[1])

# Receive and parse the public keys and ciphertexts
public_exponent1 = get_value()  # e1
modulus1 = get_value()          # n1
ciphertext1 = get_value()       # c1

public_exponent2 = get_value()  # e2
modulus2 = get_value()          # n2
ciphertext2 = get_value()       # c2

# Solve for coefficients a and b in the equation: a*e1 + b*e2 = 1
_, coefficient_a, coefficient_b = gcdext(public_exponent1, public_exponent2)

# Handle negative coefficient_b by finding modular inverse of ciphertext2
if coefficient_b < 0:
    ciphertext2 = invert(ciphertext2, modulus1)
    coefficient_b = -coefficient_b

# Combine results to recover the original message
message_integer = (powmod(ciphertext1, coefficient_a, modulus1) * 
                   powmod(ciphertext2, coefficient_b, modulus1)) % modulus1

# Convert the decrypted integer to a readable flag
message_hex = hex(message_integer)[2:]  # Strip '0x' prefix
flag = binascii.unhexlify(message_hex).decode()
print("Flag:", flag)

# Close the connection
connection.close()
