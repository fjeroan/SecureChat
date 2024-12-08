
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

shared_key = None  # AES key shared with the peer

def decrypt_message(nonce, ciphertext, tag):
    """Decrypts a message using AES-GCM."""
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_message(message, key):
    """
    Encrypts a message using AES-GCM.
    """
    nonce = os.urandom(12)  # GCM requires a 12-byte nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def receive_messages(client_socket):
    global shared_key

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if "|" in message:  # Encrypted message format
                nonce, ciphertext, tag = [base64.b64decode(part) for part in message.split("|")]
                plaintext = decrypt_message(nonce, ciphertext, tag)
                print(f"Decrypted message: {plaintext.decode()}")
            else:
                print(f"{message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()

def start_client():
    global shared_key

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    username = input("Enter your username: ")
    # Assume authentication happens here using existing methods

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        message = input()
        if message.lower() == '/exit':
            break
        elif message.startswith("/startsession"):
            # Generate shared key for encryption
            shared_key = os.urandom(32)  # Simulating key sharing (this should be handled properly)
            message = m
            client_socket.send(message.encode())
        else:
            client_socket.send(message.encode())

    client_socket.close()

if __name__ == "__main__":
    start_client()
