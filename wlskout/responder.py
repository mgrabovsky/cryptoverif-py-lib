#!/usr/bin/env python3
import base, WLSK_Resp
from common import INITIATOR, RESPONDER, SERVER, PORT, get_local_address
import socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()
    isock = socket.socket()

    responder = WLSK_Resp.init()
    isock.bind((my_addr, PORT))
    isock.listen(1)

    print('Listening on \x1b[1m{}\x1b[0m:{} as a {}'.format(my_addr, PORT, RESPONDER))
    server_addr = input('Enter {} address: '.format(SERVER))

    print('\nAwaiting connections...')
    conn, addr = isock.accept()
    print('Received connection from {0[0]}:{0[1]}'.format(addr))

    idA = conn.recv(BUFFER_SIZE)
    print("{}'s identity is {}".format(INITIATOR, idA))

    (b4, n) = responder(idA)
    print('Generating nonce...\n  n = {}'.format(n))
    conn.send(n)

    data = conn.recv(BUFFER_SIZE)
    conn.close()
    isock.close()
    (iv1, e, m) = base.decompose(data)
    print('Received secrets\n  e = {}\n  m = {}'.format(e, m))

    (b6, idA_, idB_, iv2, e_, m_) = b4(iv1, e, m)

    print('Connecting to the {}...'.format(SERVER))
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.connect((server_addr, PORT))

    print("Sending encrypted data...\n  idA' = {}\n  idB' = {}\n  e'   = {}\n  m'   = {}".format(idA_, idB_, iv2, e_, m_))
    ssock.send(base.compose([idA_, idB_, iv2, e_, m_]))

    data = ssock.recv(BUFFER_SIZE)
    ssock.close()
    (iv3, e__, m__) = base.decompose(data)
    print("Received secrets\n  e'' = {}\n  m'' = {}".format(e__, m__))

    b6(iv3, e__, m__)

