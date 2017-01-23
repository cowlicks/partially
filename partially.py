'''
This is an implemention of the partially blind signature scheme from the paper:

Provably Secure Partially Blind Signatures
Masayuki ABE and Tatsuaki OKAMOTO
'''
import os
from collections import namedtuple
import hashlib


Parameters = namedtuple('Parameters', ['L', 'N', 'p', 'q', 'g'])
Keypair = namedtuple('Keypair', ['x', 'y', 'parameters'])


### Math helper functions ###
def rand_int(nbits):
    if nbits % 8 != 0:
        raise ValueError("nbits must be divisible by 8 so it can be broken"
                         " into bytes.")
    return int.from_bytes(os.urandom(nbits//8), byteorder='little')


def rand_less_than(upper_bound, nbits):
    '''This could be smarter.'''
    while True:
        r = rand_int(nbits)
        if r < upper_bound:
            return r


def fermat_test(p, nbits):
    '''Fermat primality test'''
    for _ in range(5):
        a = rand_less_than(p, nbits)
        if not pow(a, p - 1, p) == 1:
            return False
    return True


def miller_rabin_test(p, nbits):
    '''Miller-Rabin primality test'''
    k = 5  # accuracy parameter, this should be turned up in practice
    r = 1
    while (pow(2, r) & p) != pow(2, r):
        r += 1
    d = p // pow(2, r)
    for _ in range(k):
        a = rand_less_than(p - 2, nbits)
        x = pow(a, d, p)
        if x == 1 or x == p - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == 1:
                return False
            if x == p - 1:
                break
        else:
            return False
    return True


def prime_test(p, nbits):
    return miller_rabin_test(p, nbits)


def rand_prime(nbits):
    is_prime = False
    while not is_prime:
        p = rand_int(nbits)
        is_prime = prime_test(p, nbits)
    return p


### DSA functions ###
def choose_q(N):
    return rand_prime(N)


def choose_p(L, N, q):
    k = L - N
    is_prime = False
    while not is_prime:
        p = (q*rand_int(k)) + 1
        is_prime = prime_test(p, L)
    return p


def choose_g(L, N, p, q):
    h = 2
    while True:
        g = pow(h, (p - 1)//q, p)
        if pow(g, q, p) == 1:
            return g
        h = rand_less_than(p, L)


def choose_parameters(L, N):
    '''Returns DSA parameters p, q, g'''
    q = choose_q(N)
    p = choose_p(L, N, q)
    g = choose_g(L, N, p, q)
    return Parameters(L, N, p, q, g)


def choose_keypair(parameters):
    x = rand_less_than(parameters.q, parameters.N)
    return Keypair(x, pow(parameters.g, x, parameters.p), parameters)


def int_to_bytes(in_int):
    i = in_int
    byte_length = ((i).bit_length() + 7) // 8
    return i.to_bytes(byte_length, 'little')


### Hashing functions ###
def do_hash(data):
    '''hash helper'''
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def full_domain_hash(data, target_length):
    tl_bytes = target_length // 8
    digest_size = hashlib.sha256().digest_size
    ncycles = (tl_bytes // digest_size) + 1
    out = bytearray()
    for i in range(ncycles):
        out.extend(do_hash(data + int_to_bytes(i)))
    return bytes(out[:tl_bytes])


def digest(data, parameters):
    '''F hash function from paper'''
    hashed = full_domain_hash(data, parameters.L)
    i = int.from_bytes(hashed, byteorder='little') % parameters.p
    return pow(i, (parameters.p - 1)//parameters.q, parameters.p)


### Protocol stuff ###
class Signer:
    '''Signer S from the paper'''
    def __init__(self, parameters):
        self.parameters = parameters
        self.L, self.N, self.p, self.q, self.g = tuple(parameters)
        self.keypair = choose_keypair(self.parameters)

    def one(self, info):
        usd = [rand_less_than(self.q, self.N) for _ in range(3)]
        self.u, self.s, self.d = usd

        self.z = digest(info, self.parameters)

        self.a = pow(self.g, self.u, self.p)
        self.b = (pow(self.g, self.s, self.p) *
                  pow(self.z, self.d, self.p)) % self.p
        return self.a, self.b

    def three(self, e):
        self.c = (e - self.d) % self.q
        self.r = (self.u - (self.c * self.keypair.x)) % self.q
        return self.r, self.c, self.s, self.d


class User:
    '''User U from the paper'''
    def __init__(self, parameters, pubkey):
        self.parameters = parameters
        self.L, self.N, self.p, self.q, self.g = tuple(parameters)
        self.y = pubkey

    def start(self, info, msg):
        ts = [rand_less_than(self.q, self.N) for _ in range(4)]
        self.t1, self.t2, self.t3, self.t4 = ts

        self.z = digest(info, self.parameters)
        self.msg = msg

    def two(self, a, b):
        alpha = (a * pow(self.g, self.t1, self.p) *
                 pow(self.y, self.t2, self.p)) % self.p
        beta = (b * pow(self.g, self.t3, self.p) *
                pow(self.z, self.t4, self.p)) % self.p

        e_bytes = bytearray()
        for v in (alpha, beta, self.z):
            e_bytes.extend(int_to_bytes(v))
        e_bytes.extend(msg)

        epsilon = int.from_bytes(full_domain_hash(e_bytes, self.N), 'little')
        return (epsilon - self.t2 - self.t4) % self.q

    def four(self, r, c, s, d):
        rho = (r + self.t1) % self.q
        omega = (c + self.t2) % self.q
        delta = (s + self.t3) % self.q
        sigma = (d + self.t4) % self.q
        return rho, omega, delta, sigma


def check(rho, omega, delta, sigma, z, msg, y, parameters):
    '''Signatuer verification'''
    lhs = int_to_bytes((omega + sigma) % parameters.q)

    rhs_one = (pow(parameters.g, rho, parameters.p) *
               pow(y, omega, parameters.p)) % parameters.p
    rhs_two = (pow(parameters.g, delta, parameters.p) *
               pow(z, sigma, parameters.p)) % parameters.p

    rhs_hash = full_domain_hash(int_to_bytes(rhs_one) + int_to_bytes(rhs_two) +
                                int_to_bytes(z) + msg, parameters.N)
    rhs = int_to_bytes(int.from_bytes(rhs_hash, 'little') % parameters.q)
    return rhs == lhs


if __name__ == '__main__':
    L, N = 1024, 160
    info = b'info'
    msg = b'my msg'

    params = choose_parameters(L, N)
    signer = Signer(params)

    user = User(params, signer.keypair.y)
    user.start(info, msg)

    a, b = signer.one(info)
    e = user.two(a, b)
    r, c, s, d = signer.three(e)
    rho, omega, delta, sigma = user.four(r, c, s, d)

    # p has proper form
    assert (params.p - 1) % params.q == 0
    # requirement to use this F
    assert ((params.p - 1) % params.q**2) != 0
    # test params are prime
    assert prime_test(params.p, params.L)
    assert prime_test(params.q, params.N)
    # g has proper form
    assert pow(params.g, params.q, params.p) == 1
    # z is in g
    assert pow(user.z, params.q, params.p) == 1

    # signature works
    assert check(rho, omega, delta, sigma, user.z, msg, user.y, params)
