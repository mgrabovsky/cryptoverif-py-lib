#!/usr/bin/env python3
import base, WLSK_Resp
from common import *
import random, socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()
    isock = socket.socket()

    responder = WLSK_Resp.init()
    isock.bind((my_addr, RESP_PORT))
    isock.listen(1)

    print('Listening on \x1b[1m{}\x1b[0m:{} as a {}'.format(my_addr, RESP_PORT, RESPONDER))
    server_addr = input('Enter {} address: '.format(SERVER))

    print('\nAwaiting connections...')
    conn, addr = isock.accept()
    print('Received connection from {0[0]}:{0[1]}'.format(addr))

    idA = conn.recv(BUFFER_SIZE)
    print("{}'s identity is {}".format(INITIATOR, idA))

    (b4, n) = responder(idA)
    print('Generating nonce...')
    debug('n = {}'.format(n))
    conn.send(n)

    data = conn.recv(BUFFER_SIZE)
    conn.close()
    isock.close()
    (iv1, e, m) = base.decompose(data)
    print('Received secrets')
    debug('e = {}\nm = {}'.format(e, m))

    (b6, idA_, idB_, iv2, e_, m_) = b4(iv1, e, m)

    print('Connecting to the {}...'.format(SERVER))
    ssock = socket.create_connection((server_addr, SERVER_PORT))

    print('Sending encrypted data...')
    debug("idA' = {}\nidB' = {}\ne'   = {}\nm'   = {}".format(idA_, idB_, iv2, e_, m_))
    ssock.send(base.compose([idA_, idB_, iv2, e_, m_]))

    data = ssock.recv(BUFFER_SIZE)
    ssock.close()
    (iv3, e__, m__) = base.decompose(data)
    print('Received secrets')
    debug("e'' = {}\nm'' = {}".format(e__, m__))

    b6(iv3, e__, m__)

