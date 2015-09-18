#!/usr/bin/env python3
import base
import WLSK_Keygen, WLSK_Init, WLSK_Resp, WLSK_S

if __name__ == '__main__':
    print('Generating keys')
    WLSK_Keygen.init()(base.get_hostname())
    print('  enc_key = {}\n  mac_key = {}\b  table   = {}'.format(base.read_file('wlsk_enc_key'),
        base.read_file('wlsk_mac_key'), base.read_file('keytbl')))

    print('\x1b[31m[A1]\x1b[0m')
    (a3, idA) = WLSK_Init.init()(base.get_hostname())
    print('  idA = {}'.format(idA))

    print('\x1b[34m[B2]\x1b[0m')
    (b4, n) = WLSK_Resp.init()(idA)
    print('  n = {}'.format(n))

    print('\x1b[31m[A3]\x1b[0m')
    (_, iv1, e, m) = a3(n)
    print('  e = {}\n  m = {}'.format(e, m))

    print('\x1b[34m[B4]\x1b[0m')
    (b6, idA_, idB_, iv2, e_, m_) = b4(iv1, e, m)
    print('  idA\' = {}\n  idB\' = {}\n  e\'   = {}\n  m\'   = {}'.format(idA_, idB_, e_, m_))

    print('\x1b[33m[S5]\x1b[0m')
    (_, iv3, e__, m__) = WLSK_S.init()(idA_, idB_, iv2, e_, m_)
    print('  e\'\' = {}\n  m\'\' = {}'.format(e__, m__))

    print('\x1b[34m[B6]\x1b[0m')
    b6(iv3, e__, m__)

