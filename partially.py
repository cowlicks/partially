"""
Notes:
    * I need a better prime test. I should switch to Rabbin-Miller.
    * In some cases here I get a random int that is supposed to be less than
      some upper bounding number. But I ignore this when we are doing
      arithmetic mod that upper bounding number.

"""
import os
from collections import namedtuple
import hashlib

Parameters = namedtuple('Parameters', ['L', 'N', 'p', 'q', 'g'])
Keypair = namedtuple('Keypair', ['x', 'y', 'parameters'])

def rand_int(nbits):
    if nbits % 8 != 0:
        raise ValueError("nbits must be divisible by 8 so it can be broken into bytes")
    return int.from_bytes(os.urandom(nbits//8), byteorder='little')

def rand_less_than(upper_bound, nbits):
    ''' This looks complicated :/

    We start at the MSB and choose a random value less than or equal to the
    corresponding input byte.  If its equal to the corresponding input byte, we
    set the out byte equal to this and proceed to the next byte. If it is less
    than, we set the output byte.  Then choose the remaining bytes randomly.

    '''
    nbytes = nbits // 8
    if nbits % 8 != 0:
        raise ValueError("nbits must be divisible by 8 so it can be broken into bytes")

    in_bytes = list(upper_bound.to_bytes(nbytes, byteorder='little'))
    less_bytes = []

    # choose random MSB's that are less than or equal to the upper_bound
    for i in range(nbytes):
        ub = in_bytes[i]

        rand_byte = ord(os.urandom(1))
        while rand_byte > ub:
            rand_byte = ord(os.urandom(1))

        less_bytes.append(rand_byte)

        if rand_byte < ub:
            break
        if i == nbytes - 1:
            # we accidentally choose the same number!
            # try again
            return rand_less_than(upper_bound, nbits)

    out_bytes = bytes(less_bytes) + os.urandom(nbytes - i)
    return int.from_bytes(out_bytes, 'little')


def fermat_test(p, nbits):
    """Fermat primality test"""
    a = rand_int(nbits)
    # pow can accept a base larger than the modulus, so we don't care if a < p
    return pow(a, p - 1, p) == 1

def rand_prime(nbits):
    is_prime = False
    while not is_prime:
        p = rand_int(nbits)
        is_prime = fermat_test(p, nbits)
    return p

def choose_q(N):
    return rand_prime(N)

def choose_p(L, N, q):
    k = L - N
    is_prime = False
    while not is_prime:
        p = (q*rand_int(k)) + 1
        is_prime = fermat_test(p, N)
    return p

def choose_g(L, N, p, q):
    h = 2
    while True:
        g = pow(h, (p - 1)//q, p)
        if pow(g, q, p) == 1:
            return g
        h = rand_less_than(p, N)

def choose_parameters(L, N):
    """Returns DSA parameters p, q, g"""
    q = choose_q(N)
    p = choose_p(L, N, q)
    g = choose_g(L, N, p, q)
    return Parameters(L, N, p, q, g)

def choose_keypair(parameters):
    x = rand_less_than(parameters.q, parameters.N)
    return Keypair(x, pow(parameters.g, x, parameters.p), parameters)

def digest(info, parameters):
    h = hashlib.sha256()
    h.update(info)
    hbytes = h.digest()
    hint = int.from_bytes(hbytes, byteorder='little')
    return pow(hint, (p - 1)//q, p)

class Signer:
    def __init__(self, parameters):
        self.parameters = parameters
        self.L, self.N, self.p, self.q, self.g = tuple(parameters)
        self.keypair = choose_keypair(self.parameters)

    def step_one(self, info):
        self.u, self.s, self.d = [rand_less_than(self.q, self.N) for _ in range(3)]

        self.z = digest(info, self.parameters)

        self.a = pow(self.g, self.u, self.p)
        self.b = pow(self.g, self.s, self.p) * pow(self.z, self.d, self.p) % self.p
        return self.a, self.b

if __name__ == '__main__':
    L, N = 1024, 160
    params = choose_parameters(L, N)
    kp = choose_keypair(params)

    print(tuple(params))
