from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import socket
import threading
import os


def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(f"\n{message}\n")
            else:
                print("Server has closed the connection.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()


def authenticate(client_socket, username):
    # Receive server's public key
    public_key_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(public_key_pem)
    print(public_key_pem)

    # Create an authentication token
    auth_token = f"{username}_{os.urandom(16).hex()}".encode()

    # Encrypt the token with the server's public key
    encrypted_token = server_public_key.encrypt(
        auth_token,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the encrypted token
    client_socket.send(encrypted_token)

    # Wait for the authentication response
    response = client_socket.recv(1024).decode()
    return response == "AUTH_SUCCESS"


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    username = input("Enter your username: ")
    if authenticate(client_socket, username):
        print("Authenticated successfully!")
    else:
        print("Authentication failed. Disconnecting...")
        client_socket.close()
        return

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        message = input()
        if message.lower() == 'exit':
            break
        client_socket.send(message.encode())

    client_socket.close()


if __name__ == "__main__":
    start_client()
