from pwn import *
from z3 import *

r = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1260)
print(r.recvuntil(b'NetID (something like abc123): ').decode())
r.sendline(b'vc2499')
print(r.recvuntil(b'How many of each would you like? ').decode())

args = [Int(f'arg{i}') for i in range(1, 7)]
solver = Solver()
solver.add(Sum([c * arg for c, arg in zip([215, 275, 335, 355, 420, 580], args)]) == 1605, *[arg >= 0 for arg in args])

model = solver.model() if solver.check() == sat else exit("No solution found.")
solution = " - ".join(str(model[arg]) for arg in args)
print(f"Solution: {solution}")

r.sendline(solution.encode())
print(f"Server Response:\n{r.recvall().decode()}")

