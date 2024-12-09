
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hmac
import hashlib
import socket
import threading
import os

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

# Global variable to hold the session secret for HMAC
session_secret = None

# Helper function to generate HMAC
def generate_hmac(secret, message):
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()

# Helper function to verify HMAC
def verify_hmac(secret, message, signature):
    expected_hmac = generate_hmac(secret, message)
    return hmac.compare_digest(expected_hmac, signature)


# Handles receiving of messages
def receive_messages(client_socket):
    global session_secret

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                if message == "SESSION_START":
                    # Receive the session secret
                    session_secret = client_socket.recv(4096).strip()  # Strip any extra spaces or data
                    print(f"[DEBUG] Session Secret (Client): {session_secret.hex()}")
                    print(f"[DEBUG] Session Secret (Client): {session_secret.hex()}")

                    print("Private session established. HMAC key received.")
                elif session_secret and "|HMAC:" in message:
               
                 
                    content, received_hmac = message.rsplit("|HMAC:", 1)
                    content = content.strip()  # Remove any trailing spaces or newline characters
                    received_hmac = received_hmac.strip()  # Normalize the received HMAC
                    
                    expected_hmac = generate_hmac(session_secret, content)
                    print(f"[DEBUG] Expected HMAC: {expected_hmac}")
                    print(f"[DEBUG] Received HMAC: {received_hmac}")
                    print(f"[DEBUG] Recieved message: {message}")
                    
                    if verify_hmac(session_secret, content, received_hmac):
                        print(f"\n{content} [Verified]\n")
                    else:
                        print("\nMessage verification failed. Possible tampering detected.\n")

                else:
                    print(f"\n{message}\n")
            else:
                print("Server has closed the connection.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()


# Authenticates the client with the server
def authenticate(client_socket, username):
    # Receive server's public key
    public_key_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(public_key_pem)

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

        # Include HMAC if in a private session
        if session_secret and not message.startswith("/"):
            
            hmac_signature = generate_hmac(session_secret, message)
            print(hmac_signature)
            formatted_message = f"{message}|HMAC:{hmac_signature}".strip()
            print(f"\n[DEBUG] sent message: {formatted_message}")
            client_socket.send(formatted_message.encode('utf-8'))

        else:
            client_socket.send(message.encode())


    client_socket.close()

if __name__ == "__main__":
    start_client()
