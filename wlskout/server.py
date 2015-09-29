#!/usr/bin/env python3
import base, WLSK_S
from common import *
import socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()

    server = WLSK_S.init()

    with socket.socket() as sock:
        sock.bind((my_addr, SERVER_PORT))
        sock.listen(1)

        print('Listening on \x1b[1m{}\x1b[0m:{} as a {}\n'.format(my_addr, SERVER_PORT, SERVER))

        while True:
            print('Awaiting connection...')
            conn, addr = sock.accept()
            print('Received connection from {0[0]}:{0[1]}'.format(addr))

            data = conn.recv(BUFFER_SIZE)
            (idA_, idB_, iv2, e_, m_) = base.decompose(data)
            delay()
            print('Received secrets from {}'.format(RESPONDER))
            debug("idA' = {}\nidB' = {}\ne'   = {}\nm'   = {}".format(idA_, idB_, iv2, e_, m_))

            (_, iv3, e__, m__) = server(idA_, idB_, iv2, e_, m_)
            delay()
            print('Sending secrets...')
            debug("e'' = {}\nm'' = {}".format(e__, m__))
            conn.send(base.compose([iv3, e__, m__]))
            conn.close()

            delay()
            print('\x1b[32mSession finished\x1b[0m')

