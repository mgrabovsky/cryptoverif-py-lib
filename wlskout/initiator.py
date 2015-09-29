#!/usr/bin/env python3
import base, WLSK_Init
from common import *
import socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()

    (a3, idA) = WLSK_Init.init()(base.get_hostname())
    print('Running on \x1b[1m{}\x1b[0m as an {}\nMy identity: {}\n'.format(my_addr, INITIATOR, idA))
    resp_addr = input('Enter {} address: '.format(RESPONDER))

    print('Connecting to the {}...'.format(RESPONDER))
    delay()
    with socket.create_connection((resp_addr, RESP_PORT)) as rsock:
        print('Sending my identity to the {}...'.format(RESPONDER))
        delay()
        rsock.send(idA)

        n = rsock.recv(BUFFER_SIZE)
        delay()
        print('Received nonce')
        debug('n = {}'.format(n))

        (_, iv1, e, m) = a3(n)
        print('Sending encrypted data...')
        debug('e = {}\nm = {}'.format(e, m))
        delay()
        rsock.send(base.compose([iv1, e, m]))

    print('\x1b[32mSession finished\x1b[0m')

