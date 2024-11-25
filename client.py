import socket

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Define server host and port to connect to
    host = '127.0.0.1'  # Server address
    port = 12345

    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        response = client_socket.recv(1024).decode('utf-8')
        print(f"Response from server: {response}")

        # Send a message to the server
        message = input("Enter a message for the server: ")
        client_socket.send(message.encode('utf-8'))

        #setting up the loop to communicate all the time
        notdone = True;

        while notdone:
            message = input("Enter userName or type quit to quit: ")
            if message == "quit":
                notdone = False
                break
            client_socket.send(message.encode('utf-8'))
                
            

        # Receive and print the server's response
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Response from server: {response}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the socket
        client_socket.close()

if __name__ == "__main__":
    start_client()
