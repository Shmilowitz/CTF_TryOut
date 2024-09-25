# CTF_TryOut
Writeup on Hackthebox CTF 

#MISC
##Stop Drop and Roll
```
import socket

# Configuration
BUFFER_SIZE = 1024  # Size of the buffer to read data

# Commands to respond with
commands_to_send = ["ROLL", "DROP", "STOP"]

# Create a TCP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(('83.136.254.133', 55291))  # Connect to the game

    while True:
        # Read the game's response
        data = sock.recv(BUFFER_SIZE)

        if not data:
            print("Connection closed by the server.")
            break

        # Decode the received data
        output = data.decode('utf-8')
        print(f"Game: {output.strip()}")  # Print the game's output

        # Check if the output contains specific commands
        if "FIRE" in output or "PHREAK" in output or "GORGE" in output:
            # Join the commands with a hyphen and send
            command_string = '-'.join(commands_to_send)
            sock.sendall((command_string + '\n').encode('utf-8'))  # Send commands
            print(f"Sent: {command_string}")  # Print the sent command
```

# The socket will automatically close when exiting the with block
