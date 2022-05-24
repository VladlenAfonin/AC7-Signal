from typing import Optional
from collections import namedtuple
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from pygost import gost3410
from pygost import gost34112012256
from pygost import gost3412
from pygost import mgm

CURVE = curve = gost3410.CURVES["id-tc26-gost-3410-12-512-paramSetA"]

Point     = namedtuple('Point',     ['x',
                                     'y'])

KeyPair   = namedtuple('KeyPair',   ['public_key',
                                     'private_key'])

KeyBundle = namedtuple('KeyBundle', ['identity_key',
                                     'signed_prekey',
                                     'signature',
                                     'one_time_keys'])

Session   = namedtuple('Session',   ['dh_ratchet',
                                     'root_ratchet',
                                     'sending_ratchet',
                                     'receiving_ratchet',
                                     'received'])

Message   = namedtuple('Message',   ['data',
                                     'public_key'])


def generate_keypair(nbits: int) -> KeyPair:
    private_key = gost3410.prv_unmarshal(get_random_bytes(nbits))
    public_key = Point(*gost3410.public_key(CURVE, private_key))
    return KeyPair(public_key, private_key)

def strip_key(keypair: KeyPair) -> KeyPair:
    return KeyPair(keypair.public_key, None)

def encrypt(key: bytes, message: bytes, ad: bytes) -> tuple[bytes, bytes, bytes]:
    """Returns (ct, tag, nonce)."""

    cipher = mgm.MGM(gost3412.GOST3412Kuznechik(key).encrypt,
                     gost3412.GOST3412Kuznechik.blocksize)
    nonce = mgm.nonce_prepare(get_random_bytes(16))
    seal = cipher.seal(nonce, message, ad)
    ct = seal[:-cipher.tag_size]
    tag = seal[-cipher.tag_size:]
    return ct, tag, nonce

def decrypt(key: bytes, ct: bytes, tag: bytes, nonce: bytes, ad: bytes) -> bytes:
    cipher = mgm.MGM(gost3412.GOST3412Kuznechik(key).encrypt,
                  gost3412.GOST3412Kuznechik.blocksize)
    nonce = mgm.nonce_prepare(nonce)
    return cipher.open(nonce, ct + tag, ad)


class KdfChain:
    def __init__(self, key: bytes) -> None:
        self.reset(key)

    def step(self, input: bytes) -> bytes:
        self.key, result = HKDF(self.key, 32, input, Streebog, 2)
        return result

    def reset(self, key: bytes) -> None:
        self.key = key

class DhRatchet:
    def __init__(self):
        self.current_public_key = None
        self.current_keypair = None
        self.generate_new_keypair()

    def is_same_pk(self, pk: KeyPair) -> bool:
        return self.current_public_key == pk

    def generate_new_keypair(self) -> None:
        self.current_keypair = generate_keypair(64)

    def step(self, public_key: Optional[KeyPair]=None) -> Point:
        if public_key is not None:
            self.current_public_key = public_key
        result = CURVE.exp(self.current_keypair.private_key,
                           *self.current_public_key.public_key)

        return Point(*result)

class Streebog(gost34112012256.GOST34112012256):
    """pycryptodome-совместимая обертка над хэш-функцией Стрибог."""
    
    digest_size = 32
    
    
    def __init__(self, data=None):
        """Инициализация и обновление состояния (если надо)."""
        
        super(Streebog, self).__init__()
        if data is not None:
            self.update(data)
    
    
    @staticmethod
    def new(data=None):
        """Создание нового объекта."""
        
        return Streebog(data)
