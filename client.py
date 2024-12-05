import socket
import threading

def receive_messages(client_socket):
    """
    Continuously receive messages from the server and print them.
    """
    while True:
        try:
            # Receive messages from the server
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(f"\n{message}\n")  # Print received message, ensuring it doesn't interrupt input
            else:
                # If the server closes the connection
                print("Server has closed the connection.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()

def start_client():
    """
    Starts the client, connects to the server, and allows sending/receiving messages.
    """
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define server host and port
    host = '127.0.0.1'  # Localhost
    port = 12345

    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to the server at {host}:{port}")

        # Start a thread to continuously receive messages from the server
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
        receive_thread.daemon = True  # Ensure thread exits when the main program exits
        receive_thread.start()

        # Main loop for sending messages
        while True:
            message = input()#"Enter message to send (or 'exit' to quit): ")
            if message.lower() == 'exit':
                print("Exiting...")
                break  # Exit the loop and close the connection
            # Send the message to the server
            client_socket.send(message.encode('utf-8'))

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Close the client connection
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    start_client()

from cryptography.hazmat.primitives import serialization

# Receive the server's public key
server_public_key_pem = client_socket.recv(1024)

# Load the public key
server_public_key = serialization.load_pem_public_key(server_public_key_pem)
