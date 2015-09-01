import base, crypto
import A, B, Keygen

if __name__ == '__main__':
    print('Generating shared key')
    kg = Keygen.init()
    kg()

    print('Setting up Alice')
    alice = A.init()
    print('Setting up Bob')
    bob = B.init()

    print('Message 1: A -> B')
    (pnA, iv1, ctext1) = alice(b'X')

    (retB, iv2, ctext2) = bob(iv1, ctext1)
    assert(retB is None)
    print('Message 1 Received')

    print('Message 2: B -> A')
    retA = pnA(iv2, ctext2)
    assert(retA is None)
    print('Message 2 received')

