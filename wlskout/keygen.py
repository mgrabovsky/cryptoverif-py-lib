#!/usr/bin/env python3
import base, WLSK_Keygen
from common import *

if __name__ == '__main__':
    my_hostname = base.get_hostname()

    print('Generating keys for {}...'.format(my_hostname))
    WLSK_Keygen.init()(my_hostname)
    print('Done')
    debug('enc_key = {}\nmac_key = {}\ntable   = {}'.format(base.read_file('wlsk_enc_key'),
        base.read_file('wlsk_mac_key'), base.read_file('keytbl')))

