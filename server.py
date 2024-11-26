import socket
import threading

# Global dictionary to store clients by their usernames
clients = {}
clients_lock = threading.Lock()  # Lock for thread-safe operations on the clients dictionary


def handle_client(client_socket, client_address):
    """
    Handles communication with a single client.
    """
    global clients
    print(f"Connection established with {client_address}")
    
    # Ask the client for a username and add to the clients dictionary
    client_socket.send("Please enter your username:".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8')

    with clients_lock:
        # Ensure the username is unique
        if username in clients:
            client_socket.send("Username already taken. Disconnecting.".encode('utf-8'))
            client_socket.close()
            return
        clients[username] = client_socket
        print(f"Clients connected: {list(clients.keys())}")

    # Notify the client about successful connection
    client_socket.send(f"Welcome, {username}! You are now connected.".encode('utf-8'))

    # Notify all clients of the updated client list
    broadcast_client_list()

    try:
        while True:
            # Receive a message from the client
            message = client_socket.recv(1024).decode('utf-8')
            if not message:  # If the client closes the connection
                break

            # Check for commands
            if message.startswith("/pm"):
                handle_private_message(username, message)
            elif message.startswith("/startsession"):
                handle_private_session(username, message)
            else:
                # Broadcast the message to all clients
                broadcast_message(f"{username} says: {message}", client_socket)

    except Exception as e:
        print(f"Error with client {username}: {e}")
    finally:
        # Remove the client from the dictionary when they disconnect
        with clients_lock:
            if username in clients:
                del clients[username]
                print(f"Clients connected: {list(clients.keys())}")
        
        # Notify all clients of the updated client list
        broadcast_client_list()
        
        # Notify others that the user has left
        broadcast_message(f"{username} has left the chat.", client_socket)
        client_socket.close()


def handle_private_message(sender_username, message):
    """
    Handles a private message sent by a client.
    Message format: /pm <target_username> <message>
    """
    global clients

    try:
        # Parse the message to extract the target username and the message body
        parts = message.split(" ", 2)
        if len(parts) < 3:
            clients[sender_username].send("Invalid command format. Use: /pm <target_username> <message>".encode('utf-8'))
            return

        target_username, private_message = parts[1], parts[2]

        with clients_lock:
            if target_username in clients:
                target_socket = clients[target_username]
                # Send the private message to the target user
                target_socket.send(f"[Private] {sender_username}: {private_message}".encode('utf-8'))
                # Notify the sender that the message was delivered
                clients[sender_username].send(f"Message sent to {target_username}".encode('utf-8'))
            else:
                # Notify the sender that the target user is not available
                clients[sender_username].send(f"User {target_username} not found or not connected.".encode('utf-8'))

    except Exception as e:
        print(f"Error handling private message from {sender_username}: {e}")


def handle_private_session(sender_username, message):
    """
    Starts a direct session between two clients by sharing their connection info.
    Message format: /startsession <target_username>
    """
    global clients

    try:
        # Parse the message to extract the target username
        parts = message.split(" ", 1)
        if len(parts) < 2:
            clients[sender_username].send("Invalid command format. Use: /startsession <target_username>".encode('utf-8'))
            return

        target_username = parts[1]

        with clients_lock:
            if target_username in clients:
                sender_socket = clients[sender_username]
                target_socket = clients[target_username]

                # Send connection details to both clients
                sender_socket.send(f"Starting session with {target_username}".encode('utf-8'))
                target_socket.send(f"Starting session with {sender_username}".encode('utf-8'))

                # Share IP and port information for direct connection
                sender_ip, sender_port = sender_socket.getpeername()
                target_ip, target_port = target_socket.getpeername()

                sender_socket.send(f"Peer info: {target_username} ({target_ip}:{target_port})".encode('utf-8'))
                target_socket.send(f"Peer info: {sender_username} ({sender_ip}:{sender_port})".encode('utf-8'))
            else:
                clients[sender_username].send(f"User {target_username} not found or not connected.".encode('utf-8'))
    except Exception as e:
        print(f"Error handling private session request from {sender_username}: {e}")


def broadcast_message(message, sender_socket=None):
    """
    Sends a message to all connected clients except the sender.
    """
    global clients
    with clients_lock:
        for username, client_socket in clients.items():
            if client_socket != sender_socket:
                try:
                    client_socket.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error broadcasting to client {username}: {e}")


def broadcast_client_list():
    """
    Sends the updated list of connected clients to all clients.
    """
    global clients
    with clients_lock:
        connected_clients = list(clients.keys())
        message = f"Updated client list: {connected_clients}"
        print(message)
        for username, client_socket in clients.items():
            try:
                client_socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error sending client list to {username}: {e}")


def start_server():
    """
    Starts the server and listens for incoming connections.
    """
    global clients
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define server host and port
    host = '127.0.0.1'  # Localhost
    port = 12345

    # Bind the socket to the address and port
    server_socket.bind((host, port))

    # Enable the server to accept connections
    server_socket.listen(5)  # Queue up to 5 connections
    print(f"Server is running on {host}:{port}...")

    try:
        while True:
            # Accept a client connection
            client_socket, client_address = server_socket.accept()
            # Handle the client connection in a new thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        server_socket.close()

if __name__ == "__main__":
    start_server()
