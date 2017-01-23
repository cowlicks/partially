# Provably Secure Partially Blind Signatures

This is an implementation of the paper "Provably Secure Partially Blind Signatures" by Masayuki ABE and Tatsuaki OKAMOTO.

Here is a demo of the current usage.
```python

    L, N = 1024, 160
    # Unblinded info the signer and user both agree on out of channel.
    info = b'Time to live'
    # Blinded part of the message
    msg = b'A commodity takes on, like the added meaning invested in a fetishized object, the value of the labor that went into making it.'

    params = choose_parameters(L, N)
    signer = Signer(params)
    signer.start(info)

    user = User(params, signer.keypair.y) # y is the public key
    user.start(info, msg)

    a, b = signer.one()
    e = user.two(a, b)
    r, c, s, d = signer.three(e)
    rho, omega, delta, sigma = user.four(r, c, s, d)


    assert check(rho, omega, delta, sigma, user.z, msg, user.y, params)
```
