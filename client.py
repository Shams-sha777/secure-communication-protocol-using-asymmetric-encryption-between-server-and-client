import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

HOST = '127.0.0.1'
PORT = 65432
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

server_pem = b''
while b'END PUBLIC KEY-----' not in server_pem:
    server_pem += client_socket.recv(1024)

server_public_key = serialization.load_pem_public_key(server_pem)

client_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.sendall(client_public_pem)

def receive_loop():
    while True:
        encrypted_data = client_socket.recv(256)
        if not encrypted_data:
            break
        message = private_key.decrypt(
            encrypted_data,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print(f"\n[Server]: {message.decode()}")

threading.Thread(target=receive_loop, daemon=True).start()

while True:
    msg = input("[You]: ")
    encrypted = server_public_key.encrypt(
        msg.encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    client_socket.sendall(encrypted)
