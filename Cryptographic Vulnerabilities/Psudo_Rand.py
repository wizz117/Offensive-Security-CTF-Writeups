from pwn import *
import ctypes

# Connect to the remote server
server = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1514)

# Step 1: Send the NetID
netid = b'vc2499'
server.sendlineafter(b'abc123): ', netid)

# Step 2: Predict the random number
libc = ctypes.CDLL("libc.so.6")    # Load the C standard library
current_seed = int(time.time()) + 0x19  # Compute the seed based on the challenge logic
libc.srand(current_seed)          # Seed the PRNG
predicted_number = libc.rand()    # Generate the predicted random number

# Step 3: Send the predicted number to the server
server.sendlineafter(b"Please wait a moment...", str(predicted_number).encode())

# Step 4: Switch to interactive mode to receive the flag
server.interactive()
