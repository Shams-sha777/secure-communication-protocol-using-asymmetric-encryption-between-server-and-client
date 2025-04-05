import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def handle_client(conn):

    server_public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(server_public_pem)

    client_pem = b''
    while b'END PUBLIC KEY-----' not in client_pem:
        client_pem += conn.recv(1024)

    client_public_key = serialization.load_pem_public_key(client_pem)

    def receive_loop():
        while True:
            encrypted_data = conn.recv(256)
            if not encrypted_data:
                break
            message = private_key.decrypt(
                encrypted_data,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"\n[Client]: {message.decode()}")

    threading.Thread(target=receive_loop, daemon=True).start()

    while True:
        msg = input("[You]: ")
        encrypted = client_public_key.encrypt(
            msg.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        conn.sendall(encrypted)

HOST = '127.0.0.1'
PORT = 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"[SERVER] Listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"[SERVER] Connected by {addr}")
handle_client(conn)