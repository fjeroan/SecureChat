from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hmac
import hashlib
import socket
import threading

# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# Serializing public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Global variable to hold the session secret for HMAC and encryption
session_secret = None

# AES encryption
def encrypt_message(secret, plaintext):
    iv = os.urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad plaintext to be a multiple of block size
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Concatenate IV with ciphertext

# AES decryption
def decrypt_message(secret, data):
    iv = data[:16]  # Extract IV
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# HMAC functions (unchanged)
def generate_hmac(secret, message):
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(secret, message, signature):
    expected_hmac = generate_hmac(secret, message)
    return hmac.compare_digest(expected_hmac, signature)

# Handles receiving of messages
def receive_messages(client_socket):
    global session_secret

    while True:
        try:
            data = client_socket.recv(1024)  # Always receive as raw binary
            if data:
                if session_secret:  # Private session
                    try:
                        # Debug: Log raw received data
                        print(f"Debug: Raw encrypted data received: {data}")
                        
                        # Attempt to decrypt
                        decrypted_message = decrypt_message(session_secret, data)
                        print(f"\n[Private Message] {decrypted_message}\n")
                    except Exception as e:
                        print(f"\nDecryption failed: {e}. Possible tampering detected.\n")
                else:
                    # Decode public messages as UTF-8
                    print(f"\n{data.decode('utf-8')}\n")
            else:
                print("Server has closed the connection.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()

# Client authentication (unchanged)
def authenticate(client_socket, username):
    public_key_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(public_key_pem)

    auth_token = f"{username}_{os.urandom(16).hex()}".encode()
    encrypted_token = server_public_key.encrypt(
        auth_token,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    client_socket.send(encrypted_token)
    response = client_socket.recv(1024).decode()
    return response == "AUTH_SUCCESS"

def start_client():
    global session_secret

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

        if session_secret and not message.startswith("/"):
            encrypted_message = encrypt_message(session_secret, message)
            client_socket.send(encrypted_message)
        else:
            client_socket.send(message.encode())

    client_socket.close()
    
if __name__ == "__main__":
    start_client()
