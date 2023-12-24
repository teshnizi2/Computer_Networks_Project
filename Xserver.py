import multiprocessing as mp
import socket
import logging
import ssl
import sys
import threading
import struct


def handle_tcp_conn_recv(stcp_socket, from_queue):
    while True:
        print("before recieving packet")
        packet = recv(stcp_socket)
        print("packet recieved: ", packet.decode())
        from_queue.append(packet)


def handle_tcp_conn_send(stcp_socket, to_queue):
    while True:
        if to_queue:
            packet = to_queue.pop(0)
            send(sock=stcp_socket, msg=packet)


def handle_udp_conn_send(udp_socket, udp_addr, from_queue, flag):
    while True:
        if from_queue:
            print("queue has item")
            packet = from_queue.pop(0)
            print("packet: ", packet.decode())
            udp_socket.sendto(packet, udp_addr)

            print("sent to udp server: ", packet.decode())
            flag[0] = True



def handle_udp_conn_recv(udp_socket: socket.socket, to_queue, flag):
    n = 1024
    print("before recieving udp packet")
    while True:
        if flag[0]:
            [packet, addr] = udp_socket.recvfrom(n)
            print("data from udp {}:{}".format(
                packet, addr))
            to_queue.append(packet)


def handle_start_threads(tcp_socket):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain('./cert.pem', './key.pem')
    tcp_socket_ssl = context.wrap_socket(tcp_socket , server_side=True)


    from_queue = []
    to_queue = []
    udp_socket = None
    n =10

    while True:
        b_initiation_msg = recv(tcp_socket_ssl)
        if b_initiation_msg:
            break

    print("sal: ", b_initiation_msg.decode())
    [ip, port] = b_initiation_msg.decode().split(":")

    try:
        udp_socket = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_DGRAM)
    except socket.error as e:
        logging.error(
            "(Error) Error openning the UDP socket: {}".format(e))
        logging.error(
            "(Error) Cannot open the UDP socket {}:{} or bind to it".format(ip, port))
        sys.exit(1)
    else:
        logging.info("Bind to the UDP socket {}:{}".format(ip, port))
    flag = [False]
    recv_from_tcp = threading.Thread(
        target=handle_tcp_conn_recv, args=[tcp_socket_ssl, from_queue ])
    recv_from_tcp.start()

    send_to_tcp = threading.Thread(
        target=handle_tcp_conn_send, args=[tcp_socket_ssl, to_queue])
    send_to_tcp.start()

    recv_from_udp = threading.Thread(
        target=handle_udp_conn_recv, args=[udp_socket, to_queue, flag])
    recv_from_udp.start()

    send_to_udp = threading.Thread(target=handle_udp_conn_send, args=[
                                   udp_socket, (ip, int(port)), from_queue, flag])
    send_to_udp.start()


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 9090
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    
    print("socket binded to port", port)
    server.listen()
    while True:

        Xclient_conn_socket, addr = server.accept()
        print('connected to Xclient: ', addr, Xclient_conn_socket)
        mp.Process(target=handle_start_threads,
                   args=[Xclient_conn_socket]).start()


def send(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


def recv(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)


def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data
