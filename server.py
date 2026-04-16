import socket
import threading
import base64

from RSA import encrypt_bytes
from symmetric import generate_sym_key, sym_encrypt
from integrity import compute_hash


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.secret = generate_sym_key()

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)


            pub_key_data = c.recv(4096).decode()
            n_str, e_str = pub_key_data.split(',')
            client_pub_key = (int(n_str), int(e_str))


            encrypted_secret = encrypt_bytes(self.secret, client_pub_key)


            c.send(base64.b64encode(encrypted_secret))

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:

            data = msg.encode()
            msg_hash = compute_hash(data)
            encrypted = sym_encrypt(data, self.secret)
            payload = base64.b64encode(msg_hash + encrypted)

            client.send(payload)

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(4096)

            for client in self.clients:
                if client != c:
                    client.send(msg)


if __name__ == "__main__":
    s = Server(9001)
    s.start()
