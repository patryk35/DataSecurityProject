from _sha3 import sha3_256

from configuration.configuration import PASS_SALT


def hash_pass(password, salt):
    if len(password) < 12:
        loop = 1000 + len(password)
    else:
        loop = 1000 + len(password) % 3

    salt = salt.encode()
    for i in range(loop):
        password = sha3_256(password.encode() + salt).hexdigest()
    return password

def hash_pass_simple(password):
    if len(password) < 12:
        loop = 1000 + len(password)
    else:
        loop = 1000 + len(password) % 3

    salt = PASS_SALT.encode()
    for i in range(loop):
        password = sha3_256(password.encode() + salt).hexdigest()
    return password
