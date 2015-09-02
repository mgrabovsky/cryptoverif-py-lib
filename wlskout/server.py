#!/usr/bin/env python3
import base, WLSK_S
from common import INITIATOR, RESPONDER, SERVER, PORT, get_local_address
import socket

if __name__ == '__main__':
    my_addr = get_local_address()
    sock = socket.socket()

    server = WLSK_S.init()
    sock.bind((my_addr, PORT))
    sock.listen(1)

    print('Listening on \x1b[1m{}\x1b[0m:{} as a {}\n\nAwaiting connections...'.format(my_addr, PORT, SERVER))
    conn, addr = sock.accept()
    print('Received connection from {0[0]}:{0[1]}'.format(addr))

    data = conn.recv(BUFFER_SIZE)
    (idA_, idB_, iv2, e_, m_) = base.decompose(data)
    print("Received secrets\n  idA' = {}\n  idB' = {}\n  e'   = {}\n  m'   = {}".format(idA_, idB_, iv2, e_, m_))

    (_, iv3, e__, m__) = server(idA_, idB_, iv2, e_, m_)
    print("Sending secrets...\n  e'' = {}\n m'' = {}".format(e__, m__))
    conn.send(base.compose([iv3, e__, m__]))
    conn.close()
    sock.close()

