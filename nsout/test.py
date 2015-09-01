#!/usr/bin/env python3
import base
import ONS_Keygen, ONS_AGenKey, ONS_BGenKey
import ONS_S, ONS_A, ONS_B

if __name__ == '__main__':
    print('Generating \x1b[33mserver\x1b[0m key')
    (_, pkS) = ONS_Keygen.init()()

    print('Generating \x1b[31mA\x1b[0m key')
    (_, pkA) = ONS_AGenKey.init()()

    print('Generating \x1b[34mB\x1b[0m key')
    (_, pkB) = ONS_BGenKey.init()()
    b = base.read_file('idB')

    print('\x1b[31mA:\x1b[0m Message 1')
    (oa3, hA, hB) = ONS_A.init()(b)
    print('    hA: {}\n    hB: {}'.format(hA, hB))

    print('\x1b[33mS:\x1b[0m Message 2')
    (_, rk, h2, s) = ONS_S.init()(hA, hB)

    print('\x1b[31mA:\x1b[0m Message 3')
    (oa5, c) = oa3(rk, h2, s)

    print('\x1b[34mB:\x1b[0m Message 4')
    (ob9, hB_, hA_) = ONS_B.init()(c)

    print('\x1b[33mS:\x1b[0m Message 5')
    (_, rk_, h2_, s_) = ONS_S.init()(hB_, hA_)

    print('\x1b[34mB:\x1b[0m Message 6')
    (ob11, c_) = ob9(rk_, h2_, s_)

    print('\x1b[31mA:\x1b[0m Message 7')
    (_, m) = oa5(c_)

    print('\x1b[34mB:\x1b[0m Message 8')
    ob11(m)

