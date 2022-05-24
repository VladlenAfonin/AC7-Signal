from pickle import dumps, loads
from pygost import gost3410, gost34112012512

from utility import *
from server import *



class Client:
    INITIAL_MESSAGE = '761964310n9458730853490'

    def __init__(self, phone_number: str, otk_amount: int=6) -> None:
        """Initialize new Client."""

        # Generate identity_keypair
        identity_key = generate_keypair(64)

        # Generate signed_prekey
        signed_prekey = generate_keypair(64)

        # Generate signature
        data_for_signing = dumps(strip_key(signed_prekey))
        dgst = gost34112012512.new(data_for_signing).digest()[::-1]
        signature = gost3410.sign(curve, identity_key.private_key, dgst)
        assert(gost3410.verify(CURVE, identity_key.public_key, dgst, signature))

        # Generate one_time_keys
        one_time_keys = [generate_keypair(64) for _ in range(otk_amount)]

        self.key_bundle = KeyBundle(identity_key,
                                    signed_prekey,
                                    signature,
                                    one_time_keys)

        self.phone_number = phone_number

        self.sessions = {}

    def get_key_bundle(self):
        """Returns KeyBundle without private keys."""

        ida, psk, sig, otks = self.key_bundle

        ida = strip_key(ida)
        psk = strip_key(psk)
        new_otks = [strip_key(otk) for otk in otks]

        return KeyBundle(ida, psk, sig, new_otks)

    def send_message(self, dst: str, server: Server, message: str) -> None:
        session = self.sessions[dst]

        if session.received[0]:
            session.received[0] = False
            key  = dumps(session.dh_ratchet.step())
            skey = session.root_ratchet.step(key)
            session.sending_ratchet.reset(skey)

        message_key = session.sending_ratchet.step(b'\x00' * 32)
        ciphertext = encrypt(message_key, message.encode(), b'')
        to_send = Message(dumps(ciphertext), strip_key(session.dh_ratchet.current_keypair))
        server.enqueue_message(self.phone_number, dst, to_send)

        self.sessions[dst] = session

    def receive_message(self, src: str, server: Server) -> str:
        session = self.sessions[src]

        message, public_key = server.dequeue_message(src, self.phone_number)

        if message is None:
            session.dh_ratchet.current_public_key = public_key
            self.sessions[src] = session
            return ''

        session.received[0] = True
        if not session.dh_ratchet.is_same_pk(public_key):
            key = dumps(session.dh_ratchet.step(public_key))
            session.dh_ratchet.generate_new_keypair()
            rkey = session.root_ratchet.step(key)
            session.receiving_ratchet.reset(rkey)

        message_key = session.receiving_ratchet.step(b'\x00' * 32)
        plaintext = decrypt(message_key, *loads(message), b'')

        self.sessions[src] = session
        return plaintext

    def x3dh_init_session(self, phone_number: str, server: Server) -> None:
        idka, spka, _, _ = self.key_bundle
        (idkb, spkb, sigb, otksb), index = server.get_keybundle(phone_number)
        otkb = otksb[0]

        data_for_signing = dumps(spkb)
        dgst = gost34112012512.new(data_for_signing).digest()[::-1]
        if not gost3410.verify(CURVE, idkb.public_key, dgst, sigb):
            raise ValueError('Invalid pre-signed key.')

        eka = generate_keypair(64)

        pk1 = dumps(CURVE.exp(idka.private_key, *spkb.public_key))
        pk2 = dumps(CURVE.exp(eka.private_key, *idkb.public_key))
        pk3 = dumps(CURVE.exp(eka.private_key, *spkb.public_key))
        pk4 = dumps(CURVE.exp(eka.private_key, *otkb.public_key))

        root_key = HKDF(pk1 + pk2 + pk3 + pk4, 32, b'', Streebog, 1)

        print(f'{self.phone_number}: {root_key = }\n')

        initial_message = dumps(encrypt(root_key,
                                Client.INITIAL_MESSAGE.encode(),
                                dumps(strip_key(idka) + idkb)))

        message = Message(dumps((strip_key(idka), strip_key(eka), index, initial_message)),
                          None)
        server.enqueue_message(self.phone_number, phone_number, message)

        self.sessions[phone_number] = Session(DhRatchet(),
                                              KdfChain(root_key),
                                              KdfChain(b''),
                                              KdfChain(b''),
                                              [True])

    def x3dh_init_session_finalize(self, phone_number: str, server: Server) -> None:
        message, _ = server.dequeue_message(phone_number, self.phone_number)
        idka, eka, index, initial_message = loads(message)

        idkb, spkb, sigb, otksb = self.key_bundle
        otkb = otksb.pop(index)

        # Update bundle
        self.key_bundle = KeyBundle(idkb, spkb, sigb, otksb)

        pk1 = dumps(CURVE.exp(spkb.private_key, *idka.public_key))
        pk2 = dumps(CURVE.exp(idkb.private_key, *eka.public_key))
        pk3 = dumps(CURVE.exp(spkb.private_key, *eka.public_key))
        pk4 = dumps(CURVE.exp(otkb.private_key, *eka.public_key))

        root_key = HKDF(pk1 + pk2 + pk3 + pk4, 32, b'', Streebog, 1)

        print(f'{self.phone_number}: {root_key = }\n')

        if decrypt(root_key,
                   *loads(initial_message),
                   dumps(idka + strip_key(idkb))) != Client.INITIAL_MESSAGE.encode():
            raise ValueError('Got invalid INITIAL_MESSAGE.')

        self.sessions[phone_number] = Session(DhRatchet(),
                                              KdfChain(root_key),
                                              KdfChain(b''),
                                              KdfChain(b''),
                                              [True])

        public_key = strip_key(self.sessions[phone_number].dh_ratchet.current_keypair)
        server.enqueue_message(self.phone_number,
                               phone_number,
                               Message(None, public_key))
