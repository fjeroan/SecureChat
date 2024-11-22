import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 1024


# AES helper functions
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def hmac_hash(message, key):
    h = HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


# Main client function
def start_client(client_name):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    client_socket.send(client_name.encode())

    private_key = load_pem_private_key(open(f"{client_name.lower()}_private.pem", "rb").read(), password=None)

    # Secure communication loop
    try:
        while True:
            message = input("Enter message: ")
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print("[INFO] Exiting...")
    finally:
        client_socket.close()


if __name__ == "__main__":
    client_name = input("Enter your name (Alice/Bob/Charlie): ")
    start_client(client_name)
