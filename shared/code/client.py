import socket
import time
import random

SERVER_HOST = '10.0.0.1'  # Change to server IP if remote
SERVER_PORT = 4444

def simulate_traffic():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        for i in range(10):  # Send 10 packets
            message = f"Packet {i+1}"
            s.sendall(message.encode())
            print(f"[Client] Sent: {message}")
            time.sleep(random.uniform(0.001, 0.1))  # Random delay between 0.5s to 2s
        time.sleep(1)
        s.close()

if __name__ == "__main__":

    while True:
        
        simulate_traffic()
