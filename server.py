import socket
import threading




def handle_recieve(client: socket.socket):
    n = 1024
    while True:
        print("before")
        [message, addr] = client.recvfrom(n)
        print("mesage from client: {}:{} ".format(addr, message))

        client.sendto(message, addr)
        print("mesage sent to client: {}:{} ".format(addr, message))



if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8550
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((host, port))

    print("socket binded to port", port)

    
    threading.Thread(target=handle_recieve, args=[
        server]).start()