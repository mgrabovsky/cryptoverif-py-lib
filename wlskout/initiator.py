#!/usr/bin/env python3
import base, WLSK_Keygen, WLSK_Init
from common import INITIATOR, RESPONDER, SERVER, PORT, get_local_address
import socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()
    my_hostname = base.get_hostname()

    # First we generate encryption and digest keys
    print('Generating keys...')
    WLSK_Keygen.init()(my_hostname)
    print('Done')
    print('  enc_key = {}\n  mac_key = {}\n  table   = {}\n'.format(base.read_file('wlsk_enc_key'),
        base.read_file('wlsk_mac_key'), base.read_file('keytbl')))

    # Then we can run our client process
    (a3, idA) = WLSK_Init.init()(base.get_hostname())

    print('Running on \x1b[1m{}\x1b[0m:{} as an {}\nMy identity: {}\n'.format(my_addr, PORT, INITIATOR, idA))
    resp_addr = input('Enter {} address: '.format(RESPONDER))

    # Connect to the responder
    rsock = socket.create_connection((resp_addr, PORT))
    print('Sending my identity to the {}...'.format(RESPONDER))
    rsock.send(idA)

    n = rsock.recv(BUFFER_SIZE)
    print('Received nonce\n  n = {}'.format(n))

    (_, iv1, e, m) = a3(n)
    print('Sending encrypted data...\n  e = {}\n  m = {}'.format(e, m))
    rsock.send(base.compose([iv1, e, m]))

