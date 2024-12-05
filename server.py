import socket
import threading

#Maps usernames to sockets
clients = {}  
#maps usernames to their peer
sessions = {}  

def handle_client(client_socket, client_address):
   
   # Handles communication with a single client.
   
    global clients, sessions, public_key_pem

    #client_socket.send(public_key_pem)

    print(f"Connection established with {client_address}")

   

    # Requesting username from client
    client_socket.send("Please enter your username:".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8').strip()

    
    if username in clients:
        client_socket.send("Username already taken. Disconnecting.".encode('utf-8'))
        client_socket.close()
        return

    # Adding the client to the list of connected clients
    clients[username] = client_socket
    print(f"Clients connected: {list(clients.keys())}")
    broadcast_client_list()

    client_socket.send(f"Welcome, {username}! You are now connected. Type /help to find commands".encode('utf-8'))

    #handling the client messages
    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8').strip()
            if not message:
                break

            #creating session with clients
            if message.startswith("/startsession"):
                start_private_session(username, message)
            #end session
            elif message.startswith("/end"):
                end_private_session(username)
            #send client list
            elif message.startswith("/list"):
                broadcast_client_list()
            #give list of commands to client
            elif message.startswith("/help"):
                client_socket.send("/startsession <username> - to start a session with a user\n/end - to end a private session\n/list - to see a list of connected users\n/exit - to close connection with server".encode('utf-8'))
            #exit
            elif message == "/exit":
                break
            else:
                route_message(username, message)

    except Exception as e:

        print(f"Error with client {username}: {e}")
    
    finally:
        
        #closing the sockets
        disconnect_client(username)
        client_socket.close()


#start private session
def start_private_session(sender, message):
   
    global sessions

    parts = message.split(" ", 1)
    if len(parts) < 2:
        clients[sender].send("Usage: /startsession <username>".encode('utf-8'))
        return

    target = parts[1]

    if target not in clients:
        clients[sender].send(f"User {target} is not connected.".encode('utf-8'))
        return

    if sender in sessions or target in sessions:
        clients[sender].send("One of you is already in a session.".encode('utf-8'))
        return

    # Establishing the session
    sessions[sender] = target
    sessions[target] = sender
    clients[sender].send(f"Private session started with {target}.".encode('utf-8'))
    clients[target].send(f"Private session started with {sender}.".encode('utf-8'))


#ends private session
def end_private_session(username):

    global sessions

    if username in sessions:
        peer = sessions.pop(username)
        sessions.pop(peer, None)

        clients[username].send("Private session ended.".encode('utf-8'))
        clients[peer].send("Private session ended.".encode('utf-8'))

    
#Routes the message
def route_message(sender, message):

    if sender in sessions:

        
        peer = sessions[sender]
        if peer in clients:
            try:
                clients[peer].send(f"[Private] {sender}: {message}".encode('utf-8'))
            except Exception as e:
                print(f"Error sending private message to {peer}: {e}")
                end_private_session(sender)
        else:
            clients[sender].send("Your peer has disconnected.".encode('utf-8'))
            end_private_session(sender)
    else:
        broadcast_message(f"{sender}: {message}", exclude=sender)

#sends message to all connected clients
def broadcast_message(message, exclude=None):

    for user, client in clients.items():
        if user != exclude:
            try:
                client.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error broadcasting to {user}: {e}")


#sends client list whenever client requests it
def broadcast_client_list():

    client_list = list(clients.keys())
    message = f"Updated client list: {client_list}"
    for client in clients.values():
        try:
            client.send(message.encode('utf-8'))
        except Exception as e:
            print(f"Error broadcasting client list: {e}")


def disconnect_client(username):

    global clients, sessions

    if username in clients:
        del clients[username]

    if username in sessions:
        end_private_session(username)

    broadcast_client_list()
    print(f"{username} disconnected.")


def start_server():
  
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    print("Server is running on 127.0.0.1:12345...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        server_socket.close()


if __name__ == "__main__":
    start_server()


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Extract the public key
public_key = private_key.public_key()

# Serialize the public key for sending to clients
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize the private key for internal use
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def authenticate_client(client_socket):
    # Receive encrypted token
    encrypted_token = client_socket.recv(1024)

    # Decrypt the token using the server's private key
    try:
        decrypted_token = private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted token: {decrypted_token.decode('utf-8')}")
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False

