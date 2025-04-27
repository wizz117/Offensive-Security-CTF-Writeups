from pwn import *

def main():
    conn = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1273)
    conn.sendlineafter(b'NetID (something like abc123): ', b'vc2499')

    # Q1 input
    conn.sendlineafter(b'The first round requires two inputs...\n > ', b'flag.txt')
    conn.sendlineafter(b' > ', b'0')

    # finding fd 
    Q1_output = conn.recvuntil(b'The second phase requires a single input...\n > ')
    print("Q1 Response:\n" + Q1_output.decode('latin1'))
    fd_value = int.from_bytes(Q1_output.split(b'interior...\n')[1][:4], 'little', signed=True)

    # Q2 input
    Q2_input = ((~fd_value) ^ 0xC9) & 0xFF
    conn.send(bytes([Q2_input]))
    print("Q2 Response:\n" + conn.recvuntil(b'final level requires another single input...\n > ').decode('latin1'))

    # Q3: Send input "\x02"
    conn.send(bytes([2]))
    print("Q3 Response:\n" + conn.recvall().decode('latin1'))

    conn.close()

if __name__ == '__main__':
    main()

