#!/usr/bin/env python3
# ...

if __name__ == '__main__':
    # ...

    print('\x1b[34mB2\x1b[0m')
    (b4, n) = WLSK_Resp.init()(idA)
    print('  n = {}'.format(n))

    print('\x1b[31mA3\x1b[0m')
    (_, iv1, e, m) = a3(n)
    print('  e = {}\n  m = {}'.format(e, m))

    print('\x1b[34mB4\x1b[0m')
    (b6, idA_, idB_, iv2, e_, m_) = b4(iv1, e, m)
    print('  idA\' = {}\n  idB\' = {}\n  e\'   = {}\n  m\'   = {}'.format(idA_, idB_, e_, m_))

    print('\x1b[33mS5\x1b[0m')
    (_, iv3, e__, m__) = WLSK_S.init()(idA_, idB_, iv2, e_, m_)
    print('  e\'\' = {}\n  m\'\' = {}'.format(e__, m__))

    print('\x1b[34mB6\x1b[0m')
    b6(iv3, e__, m__)

