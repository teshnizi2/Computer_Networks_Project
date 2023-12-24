import socket
import threading

n = 10


def send_udp(client: socket.socket, msg, addr, flag):
    i = 0
    mx = len(msg)
    while True:
        curr_msg = msg[n*i: min(n*(i+1), mx)]
        client.sendto(str.encode(curr_msg), addr)
        flag[0] = True
        if(i*(n+1) >= mx):
            return
        i = i+1


def handle_send(client: socket.socket, addr, flag):

    while True:

        message = input("enter your msg:")

        send_udp(client=client, msg=message, addr=addr, flag=flag)

        print("mesage send to server: {}".format(message))


def handle_recv(client: socket.socket, flag):

    n_2 = 1024
    while True:
        if(flag[0]):
            [message, address] = client.recvfrom(n_2)

            print("mesage from server: {}:{}".format(message, address))


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8551
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (host, port)

    flag = [False]

    threading.Thread(target=handle_send, args=[client, addr, flag]).start()
    threading.Thread(target=handle_recv, args=[client, flag]).start()
