#!/usr/bin/env python3
import base, WLSK_Resp
from common import INITIATOR, RESPONDER, SERVER, PORT, get_local_address
import socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()
    sock = socket.socket()

    responder = WLSK_Resp.init()
    sock.bind((my_addr, PORT))
    sock.listen(1)

    print('Running on \x1b[1m{}\x1b[0m:{} as a {}\n\nAwaiting connections...'.format(my_addr, PORT, RESPONDER))
    conn, addr = sock.accept()
    print('Received connection from {0[0]}:{0[1]}'.format(addr))

    idA = sock.recv(BUFFER_SIZE)
    print("{}'s identity is {}".format(INITIATOR, idA))

