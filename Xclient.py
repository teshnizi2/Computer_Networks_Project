import multiprocessing as mp
import socket
import logging
import ssl
import time
import sys
import argparse
import time
import threading
import ssl
import struct


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-ut', '--udp-tunnel', action='append', required=True,
                        help="Make a tunnel from the client to the server. The format is\
                              'listening ip:listening port:remote ip:remote port'.")
    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    args = parser.parse_args()
    return args


def read_n_byte_from_tcp_sock(sock, n):
    '''Just for read n byte  from tcp socket'''
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff



def handle_tcp_conn_recv(stcp_socket, to_queue):
    while True:
        print("before recieving packet")
        packet = recv(stcp_socket)
        print("packet recieved: ", packet.decode())
        to_queue.append(packet)


def handle_tcp_conn_send(stcp_socket, rmt_udp_addr, from_queue):
    while len(from_queue) <= 0:
        x = 2
    ip_port = rmt_udp_addr[0]+":"+str(rmt_udp_addr[1])
    initiation_byte_array = bytearray()
    initiation_byte_array.extend(ip_port.encode())

    logging.info("(info) packet ready to send to Xserver {}".format(ip_port))
    send(sock=stcp_socket, msg=initiation_byte_array)
    logging.info("(info) packet initiation sucssesful")

    while True:
        if from_queue:
            packet = from_queue.pop(0)
            send(sock=stcp_socket, msg=packet)


def handle_udp_conn_send(udp_socket,udp_addr , to_queue ):
    while True:
        if to_queue:
            print(" to_queue has item")
            packet = to_queue.pop(0)
            print("to_queue packet: ", packet.decode())
            udp_socket.sendto(packet, udp_addr[0])
            print("sent to udp client: ", packet.decode())



def handle_udp_conn_recv(udp_socket: socket.socket, from_queue , address , n):
    
    logging.info("before recieving udp packet")
    while True:
        
        # print(1)
        [packet, addr] = udp_socket.recvfrom(n)
        if(len(address)<=0):
            address.append(addr)
        # print(2)
        logging.info("data from udp {}:{}".format(
            packet, addr))
        from_queue.append(packet)
        # print(3)


def get_socket_id(socket: socket.socket):
    [ip, port] = socket.getsockname()
    return ip + ":" + str(port)


def handle_start_threads(udp_socket, tcp_server_addr, rmt_udp_addr):
    format = "%(asctime)s: (%(levelname)s) %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")
    id = get_socket_id(udp_socket)
    from_udp_queue = []
    to_udp_queue = []
    stcp_socket = None
    # print("1")
    try:

        stcp_socket = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_STREAM)


        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_verify_locations('./cert.pem', './key.key')
        stcp_socket_ssl = context.wrap_socket(stcp_socket  ,server_hostname=tcp_server_addr[0])

        stcp_socket_ssl.connect(tcp_server_addr)
        # print("3")
    except socket.error as e:
        logging.error(
            "(Error) Error openning the TCP socket: {}".format(e))
        logging.error("(Error) Cannot open the TCP socket {}:{} or bind to it".format(
            tcp_server_addr[0], tcp_server_addr[1]))
        sys.exit(1)
    else:
        # print("5")
        logging.info("Bind to the TCP socket {}:{}".format(
            tcp_server_addr[0], tcp_server_addr[1]))
    udp_addr = []
    n =1024

    recv_from_udp = threading.Thread(target=handle_udp_conn_recv, args=[
                                     udp_socket,  from_udp_queue , udp_addr ,n])
    recv_from_udp.start()

    recv_from_tcp = threading.Thread(target=handle_tcp_conn_recv, args=[
                                     stcp_socket_ssl, to_udp_queue])
    recv_from_tcp.start()

    send_to_udp = threading.Thread(target=handle_udp_conn_send, args=[
                                   udp_socket ,udp_addr , to_udp_queue])
    send_to_udp.start()

    send_to_tcp = threading.Thread(target=handle_tcp_conn_send, args=[
        stcp_socket_ssl, rmt_udp_addr, from_udp_queue])
    send_to_tcp.start()



if __name__ == "__main__":
    args = parse_input_argument()

    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    tcp_server_addr = (tcp_server_ip, tcp_server_port)

    if args.verbosity == 'error':
        log_level = logging.ERROR
    elif args.verbosity == 'info':
        log_level = logging.INFO
    elif args.verbosity == 'debug':
        log_level = logging.DEBUG
    format = "%(asctime)s: (%(levelname)s) %(message)s"
    logging.basicConfig(format=format, level=log_level, datefmt="%H:%M:%S")
    socket_infos = {}

    for tun_addr in args.udp_tunnel:
        tun_addr_split = tun_addr.split(':')
        udp_listening_ip = tun_addr_split[0]
        udp_listening_port = int(tun_addr_split[1])
        rmt_udp_ip = tun_addr_split[2]
        rmt_udp_port = int(tun_addr_split[3])
        rmt_udp_addr = (rmt_udp_ip, rmt_udp_port)

        try:
            udp_socket = socket.socket(
                family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((udp_listening_ip, udp_listening_port))
        except socket.error as e:
            logging.error(
                "(Error) Error openning the UDP socket: {}".format(e))
            logging.error("(Error) Cannot open the UDP socket {}:{} or bind to it".format(
                udp_listening_ip, udp_listening_port))
            sys.exit(1)
        else:
            logging.info("Bind to the UDP socket {}:{}".format(
                udp_listening_ip, udp_listening_port))
        # print(udp_socket.getsockname())
        # print(udp_socket.getpeername())

        mp.Process(target=handle_start_threads,
                   args=(udp_socket, tcp_server_addr, rmt_udp_addr)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Closing the TCP connection...")


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
