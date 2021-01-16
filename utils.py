from base64 import *
from hashlib import *
from typing import Union
from Crypto.Cipher import AES
from Crypto import Random


def code(msg: str, base: int) -> bytes:
    if base == 64:
        return b64encode(msg.encode('ascii'))
    elif base == 32:
        return b32encode(msg.encode('ascii'))
    elif base == 16:
        return b16encode(msg.encode('ascii'))
    else:
        raise Exception("Wrong Base")


def decode(coded_msg: str, base: int) -> str:
    if base == 64:
        return b64decode(coded_msg.encode('ascii')).decode("utf-8")
    elif base == 32:
        return b32decode(coded_msg.encode('ascii')).decode("utf-8")
    elif base == 16:
        return b16decode(coded_msg.encode('ascii')).decode("utf-8")
    else:
        raise Exception("Wrong Base")


def hash_msg(msg: str, algo: str) -> str:
    if algo == "SHA256":
        return sha3_256(msg.encode('ascii')).hexdigest()
    elif algo == "SHA512":
        return sha3_512(msg.encode('ascii')).hexdigest()
    elif algo == "BLAKE2b":
        return blake2b(msg.encode('ascii')).hexdigest()
    elif algo == "BLAKE2s":
        return blake2s(msg.encode('ascii')).hexdigest()
    elif algo == "MD5":
        return md5(msg.encode('ascii')).hexdigest()


def search_for_original(hashed_msg: str, algo: str, dict_path: str = "pentbox-wlist.txt") -> Union[None, str]:
    hash_method = None
    if algo == "SHA256":
        hash_method = sha3_256
    elif algo == "SHA512":
        hash_method = sha3_512
    elif algo == "BLAKE2b":
        hash_method = blake2b
    elif algo == "BLAKE2s":
        hash_method = blake2s
    elif algo == "MD5":
        hash_method = md5
    with open(dict_path, 'r') as file:
        for word in file:
            word = word[:-1]
            if hash_method(word.encode('ascii')).hexdigest() == hashed_msg:
                return word
    return None


def aes_encryption():
    pass


def symmetric_encryption():
    pass
