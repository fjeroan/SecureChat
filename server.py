import socket
import threading
import sys

# Global list to store connected clients
clients = []
clients_lock = threading.Lock()  # Lock for thread-safe operations on the clients list
server_socket = None  # To store the server socket

def handle_client(client_socket, client_address):
    """
    Handles communication with a single client.
    """
    global clients
    print(f"Connection established with {client_address}")
    
    # Add the client to the list of connected clients
    with clients_lock:
        clients.append((client_socket, client_address))
        print(f"Clients connected: {[addr for _, addr in clients]}")

    # Send the list of connected clients to the new client
    with clients_lock:
        # Exclude the new client from the list sent to the client
        connected_clients = [addr for _, addr in clients if addr != client_address]
        client_list_message = f"Connected clients: {connected_clients}"
        client_socket.send(client_list_message.encode('utf-8'))

    try:
        while True:
            # Receive message from client
            message = client_socket.recv(1024).decode('utf-8')
            if not message:  # If the client closes the connection
                break
            print(f"Message from {client_address}: {message}")

            # Broadcast the message to all connected clients (optional feature)
            broadcast_message(f"{client_address} says: {message}", client_socket)

            # Send an acknowledgment back to the sender
            response = f"Server received: {message}"
            client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f"Error with client {client_address}: {e}")
    finally:
        # Remove the client from the list when they disconnect
        with clients_lock:
            clients = [c for c in clients if c[0] != client_socket]
            print(f"Clients connected: {[addr for _, addr in clients]}")
        
        # Close the connection
        print(f"Connection closed with {client_address}")
        client_socket.close()

def broadcast_message(message, sender_socket):
    """
    Sends a message to all connected clients except the sender.
    """
    global clients
    with clients_lock:
        for client_socket, _ in clients:
            if client_socket != sender_socket:  # Don't send the message back to the sender
                try:
                    client_socket.send(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error broadcasting to client: {e}")

def stop_server():
    """
    Stops the server and closes all client connections.
    """
    global server_socket, clients
    print("Shutting down the server...")

    # Close all client connections
    with clients_lock:
        for client_socket, _ in clients:
            client_socket.close()

    # Close the server socket
    if server_socket:
        server_socket.close()

    print("Server stopped.")

def start_server():
    """
    Starts the server and listens for incoming connections.
    """
    global server_socket
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
        # Catch the Ctrl + C interrupt to shut down the server gracefully
        print("\nServer is shutting down...")
        stop_server()
        sys.exit(0)  # Exit the program

if __name__ == "__main__":
    start_server()
