#!/usr/bin/env python3
import base, WLSK_Keygen, WLSK_Init
from common import *
import random, socket

BUFFER_SIZE = 1024

if __name__ == '__main__':
    my_addr = get_local_address()
    my_hostname = base.get_hostname()

    '''
    # First we generate encryption and digest keys
    print('Generating keys...')
    WLSK_Keygen.init()(my_hostname)
    print('Done')
    debug('enc_key = {}\nmac_key = {}\ntable   = {}\n'.format(base.read_file('wlsk_enc_key'),
        base.read_file('wlsk_mac_key'), base.read_file('keytbl')))
    '''

    # Then we can run our client process
    (a3, idA) = WLSK_Init.init()(base.get_hostname())

    print('Running on \x1b[1m{}\x1b[0m as an {}\nMy identity: {}\n'.format(my_addr, INITIATOR, idA))
    resp_addr = input('Enter {} address: '.format(RESPONDER))

    # Connect to the responder
    rsock = socket.create_connection((resp_addr, RESP_PORT))
    print('Sending my identity to the {}...'.format(RESPONDER))
    rsock.send(idA)

    n = rsock.recv(BUFFER_SIZE)
    print('Received nonce')
    debug('n = {}'.format(n))

    (_, iv1, e, m) = a3(n)
    print('Sending encrypted data...')
    debug('e = {}\nm = {}'.format(e, m))
    rsock.send(base.compose([iv1, e, m]))

