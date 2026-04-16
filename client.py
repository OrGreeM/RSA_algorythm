import socket
import sys
import threading
import base64

from RSA import generate_keys, decrypt_bytes
from symmetric import sym_encrypt, sym_decrypt
from integrity import compute_hash, verify_hash


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        self.public_key, self.private_key = generate_keys(1024)

        n, e = self.public_key
        self.s.send(f"{n},{e}".encode())

        encrypted_secret = base64.b64decode(self.s.recv(4096))
        self.secret = decrypt_bytes(encrypted_secret, self.private_key)

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(4096)


            raw = base64.b64decode(message)
            msg_hash = raw[:32]
            encrypted = raw[32:]
            plaintext = sym_decrypt(encrypted, self.secret)

            if not verify_hash(plaintext, msg_hash):
                print("[!] message integrity check failed")
                continue

            print(plaintext.decode())

    def write_handler(self):
        while True:
            message = input()

            full = f"{self.username}: {message}".encode()
            msg_hash = compute_hash(full)
            encrypted = sym_encrypt(full, self.secret)
            payload = base64.b64encode(msg_hash + encrypted)

            self.s.send(payload)


if __name__ == "__main__":
    username = sys.argv[1]
    cl = Client("127.0.0.1", 9001, username)
    cl.init_connection()
