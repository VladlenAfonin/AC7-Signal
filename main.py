from server import *
from client import *


def main():
    server = Server()
    alice  = Client('+79874131267')
    bob    = Client('+18750008972')

    server.register(alice.phone_number, alice.get_key_bundle())
    server.register(bob.phone_number, bob.get_key_bundle())

    # Perform X3DH
    alice.x3dh_init_session(bob.phone_number, server)

    print(f'{server.messages = }\n')

    bob.x3dh_init_session_finalize(alice.phone_number, server)

    print(f'{server.messages = }\n')

    alice.receive_message(bob.phone_number, server)


    # Communicate
    alice.send_message(bob.phone_number, server, 'Hello!')

    print(f'{server.messages = }\n')

    print(bob.receive_message(alice.phone_number, server))

    print(f'{server.messages = }\n')

    bob.send_message(alice.phone_number, server, 'Hi!')
    bob.send_message(alice.phone_number, server, 'How are you?')
    bob.send_message(alice.phone_number, server, 'How was your day?')

    print(f'{server.messages = }\n')

    # alice.sessions[bob.phone_number].root_ratchet.key = b'' # <- BREAK ROOT_RATCHET

    print(alice.receive_message(bob.phone_number, server))
    # alice.sessions[bob.phone_number].receiving_ratchet.key = b'' # <- BREAK RECIEVING_CHAIN
    print(alice.receive_message(bob.phone_number, server))
    print(alice.receive_message(bob.phone_number, server))

    print(f'{server.messages = }\n')

    alice.send_message(bob.phone_number, server, 'I am good!')
    alice.send_message(bob.phone_number, server, 'And how are you?')

    print(f'{server.messages = }\n')

    print(bob.receive_message(alice.phone_number, server))
    print(bob.receive_message(alice.phone_number, server))

    print(f'{server.messages = }\n')

if __name__ == '__main__':
    main()
