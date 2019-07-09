#!/usr/bin/env python3

# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus
# ------------------------------------------------
# Added fastecdsa - June 2019 - Ian McMurray
# https://github.com/imcmurray/Plutus-fastecdsa
# ------------------------------------------------
# Added convert to pickle from csv - July 2019 - AirShark
# https://github.com/AirShark/Plutus

import os
try:
    import cPickle as pickle
except ImportError:
    import _pickle as pickle
import hashlib
import binascii
import multiprocessing

# using fastecdsa instead of starkbank
from fastecdsa import curve, keys


DATABASE = r'database/JUL_06_2019/'


def generate_private_key():
    """
    Generate a random 32-byte hex integer which serves as a randomly
    generated Bitcoin private key.
    Average Time: 0.0000061659 seconds
    """
    return keys.gen_private_key(curve.secp256k1)


def private_key_to_public_key(private_key):
    """
    Accept a hex private key and convert it to its respective public key.
    Because converting a private key to a public key requires SECP256k1 ECDSA
    signing, this function is the most time consuming and is a bottleneck in
    the overall speed of the program.
    Average Time: 0.0016401287 seconds
    """
    # get the public key corresponding to the private key we just generated
    _c = int('0x%s' % private_key, 0)
    _d = keys.get_public_key(_c, curve.secp256k1)
    return '04%s%s' % ('{0:x}'.format(int(_d.x)), '{0:x}'.format(int(_d.y)))


def public_key_to_address(public_key):
    """
    Accept a public key and convert it to its resepective P2PKH wallet address.
    Average Time: 0.0000801390 seconds
    """
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    try:
        encoding = binascii.unhexlify(public_key.encode())
        var.update(hashlib.sha256(encoding).digest())
        var_encoded = ('00' + var.hexdigest()).encode()
        digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
        var_hex = '00' + var.hexdigest() + \
            hashlib.sha256(digest).hexdigest()[0:8]
        _count = [char != '0' for char in var_hex].index(True) // 2
        _n = int(var_hex, 16)
        while _n > 0:
            _n, remainder = divmod(_n, 58)
            output.append(alphabet[remainder])
        for _i in range(_count):
            output.append(alphabet[0])
        return ''.join(output[::-1])
    except:
        # Skip if public_key gen caused an error - I think this happens
        # because urandom was smaller than 32 bytes?
        return -1


def process(private_key, public_key, address, _database):
    """
    Accept an address and query the database. If the address is found in the
    database, then it is assumed to have a balance and the wallet data is
    written to the hard drive. If the address is not in the database, then it
    is assumed to be empty and printed to the user.
    Average Time: 0.0000026941 seconds
    """
    if address in _database[0] or \
       address in _database[1] or \
       address in _database[2] or \
       address in _database[3] or \
       address in _database[4]:
        with open('plutus.txt', 'a') as _file:
            _file.write('hex PrivateKey: ' + str(private_key) + '\n' +
                        'WIF PrivateKey: ' + str(private_key_to_wif(private_key)) + '\n' +
                        'Public key: ' + str(public_key) + '\n' +
                        'address: ' + str(address) + '\n\n')
    else:
        # Is printing every address slowing the process down since it has to
        # write to STDOUT?
        # print(str(private_key),":",str(address))
        print('\r' + str(address), end='', flush=True)


def private_key_to_wif(private_key):
    """
    Convert the hex private key into Wallet Import Format for easier wallet
    importing. This function is only called if a wallet with a balance is
    found. Because that event is rare, this function is not significant to the
    main pipeline of the program and is not timed.
    """
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for _i, _c in enumerate(var[::-1]):
        value += 256**_i * _c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for _c in var:
        if _c == 0:
            pad += 1
        else:
            break
    return chars[0] * pad + result


def main(_database):
    """
    Create the main pipeline by using an infinite loop to repeatedly call the
    functions, while utilizing multiprocessing from __main__. Because all the
    functions are relatively fast, it is better to combine them all into
    one process.
    """
    while True:
        # 0.0000061659 seconds
        private_key = generate_private_key()
        # 0.0016401287 seconds
        public_key = private_key_to_public_key(private_key)
        # 0.0000801390 seconds
        address = public_key_to_address(public_key)
        if address != -1:
            # 0.0000026941 seconds
            process(private_key, public_key, address, _database)
        # --------------------
        # 0.0017291287 seconds


if __name__ == '__main__':
    """
    Deserialize the database and read into a list of sets for easier selection
    and O(1) complexity. Initialize the multiprocessing to target the main
    function with cpu_count() concurrent processes.
    """

    _DATABASE = [set() for _ in range(5)]
    _COUNT = len(os.listdir(DATABASE))
    _HALF = _COUNT // 2
    _QUARTER = _HALF // 2
    for c, p in enumerate(os.listdir(DATABASE)):
        print('\rreading database: ' + str(c + 1) + '/' + str(_COUNT), end=' ')
        with open(DATABASE + p, 'rb') as file:
            if c + 1 == 21:  # HOOK
                _DATABASE[4] = _DATABASE[4] | pickle.load(file)  # HOOK
                continue  # HOOK
            if c < _HALF:
                if c < _QUARTER:
                    _DATABASE[0] = _DATABASE[0] | pickle.load(file)
                else:
                    _DATABASE[1] = _DATABASE[1] | pickle.load(file)
            else:
                if c < _HALF + _QUARTER:
                    _DATABASE[2] = _DATABASE[2] | pickle.load(file)
                else:
                    _DATABASE[3] = _DATABASE[3] | pickle.load(file)
    print('DONE')

    # To verify the database size, remove the # from the line below
    # print('database size: ' + str(sum(len(i) for i in _DATABASE))); quit()

    for cpu in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=main, args=(_DATABASE, )).start()
