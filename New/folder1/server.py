import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import base64

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

# Public keys of the clients
client_public_keys = {
    "Alice": load_pem_public_key(open("alice_public.pem", "rb").read()),
    "Bob": load_pem_public_key(open("bob_public.pem", "rb").read()),
    "Charlie": load_pem_public_key(open("charlie_public.pem", "rb").read()),
}

clients = {}  # Active client sockets
sessions = {}  # Session keys

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

# Handle client communication
def handle_client(client_socket, client_name):
    print(f"[INFO] {client_name} connected.")
    try:
        while True:
            encrypted_message = client_socket.recv(BUFFER_SIZE)
            if not encrypted_message:
                break

            # Decrypt the message and verify HMAC
            session_key = sessions[client_name]["key"]
            received_hmac = encrypted_message[-32:]
            encrypted_message = encrypted_message[:-32]

            if hmac_hash(encrypted_message, session_key) != received_hmac:
                print("[ERROR] Message integrity failed.")
                continue

            decrypted_message = decrypt_message(encrypted_message, session_key).decode()
            print(f"[MESSAGE] {client_name}: {decrypted_message}")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()
        del clients[client_name]

# Establish session
def establish_session(client_socket, initiator, recipient):
    if recipient not in clients:
        client_socket.send("[ERROR] Recipient is not online.".encode())
        return

    if recipient in sessions or initiator in sessions:
        client_socket.send("[ERROR] One of the clients is already in a session.".encode())
        return

    # Generate session key and distribute
    session_key = os.urandom(32)
    sessions[initiator] = {"key": session_key, "peer": recipient}
    sessions[recipient] = {"key": session_key, "peer": initiator}

    # Send session key encrypted using RSA
    recipient_key = client_public_keys[recipient]
    initiator_key = client_public_keys[initiator]

    encrypted_key_initiator = initiator_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_key_recipient = recipient_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    clients[initiator].send(encrypted_key_initiator)
    clients[recipient].send(encrypted_key_recipient)
    print(f"[INFO] Session established between {initiator} and {recipient}.")

# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[INFO] Server started on {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_name = client_socket.recv(BUFFER_SIZE).decode()

            # Authenticate client
            if client_name not in client_public_keys:
                client_socket.send("[ERROR] Authentication failed.".encode())
                client_socket.close()
                continue

            clients[client_name] = client_socket
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_name))
            client_thread.start()
    except KeyboardInterrupt:
        print("[INFO] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
