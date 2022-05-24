from utility import *
from Crypto.Random import random


class Server:
    """Server model."""

    def __init__(self) -> None:
        """Initialize new Server."""

        # phone_number -> key_bundle
        self.key_bundles = {}

        # (src_phone_number, dst_phone_number) -> message: Message
        self.messages = {}

        # phone_number -> ek: KeyPair
        self.eks = {}

    def register(self, phone_number: str, key_bundle: KeyBundle) -> None:
        """Registers a new user."""

        if phone_number in self.key_bundles:
            raise ValueError('Phone number already exists.')

        self.key_bundles[phone_number] = key_bundle

    def get_keybundle(self, phone_number: str) -> tuple[KeyBundle, int]:
        key_bundle = self.key_bundles[phone_number]
        otks = key_bundle.one_time_keys

        index = random.randint(0, len(otks) - 1)
        otk = otks.pop(index)

        self.key_bundles[phone_number] = KeyBundle(key_bundle.identity_key,
                                                   key_bundle.signed_prekey,
                                                   key_bundle.signature,
                                                   otks)

        key_bundle = KeyBundle(key_bundle.identity_key,
                               key_bundle.signed_prekey,
                               key_bundle.signature,
                               [otk])

        return key_bundle, index

    def enqueue_message(self, src: str, dst: str, message: Message) -> None:
        search_key = (src, dst)
        if search_key not in self.messages:
            self.messages[search_key] = []

        self.messages[search_key].append(message)

    def dequeue_message(self, src: str, dst: str) -> Message:
        return self.messages[(src, dst)].pop(0)

    def store_ek(self, phone_number: str, ek: KeyPair) -> None:
        self.eks[phone_number] = ek

    def get_ek(self, phone_number: str) -> KeyPair:
        return self.eks[phone_number]
