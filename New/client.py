import socket
import threading

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(BUFFER_SIZE).decode()
            if not message:
                break
            print(message)
        except ConnectionError:
            print("[INFO] Disconnected from the server.")
            break

# Main client function
def start_client(client_name):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Send client name to the server
    client_socket.send(client_name.encode())

    # Start a thread to listen for messages from the server
    threading.Thread(target=receive_messages, args=(client_socket,)).start()

    try:
        while True:
            # Send a message to the server
            message = input()
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print("[INFO] Exiting...")
    finally:
        client_socket.close()

if __name__ == "__main__":
    client_name = input("Enter your name: ")
    start_client(client_name)
