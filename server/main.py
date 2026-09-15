HOST = ''
PORT = 1265

import socket
import struct
import uuid
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def createResponse(code, client_id=None, aes_key=None, content_size=None, file_name=None, cksum=None):
    if code == 1600 or code == 1604 or code == 1606:
        return struct.pack("<BHI16s", 3, code, 16, client_id)
    elif code == 1602 or code == 1605:
        key_len = len(aes_key)
        structure = f"<BHI16s{key_len}s"
        return struct.pack(structure, 3, code, 16 + key_len, client_id, aes_key)
    elif code == 1603:
        return struct.pack("<BHI16sI255sI", 3, code, 279, client_id, content_size, file_name, cksum)
    elif code == 1601 or code == 1607:
        return struct.pack("<BHI", 3, code, 0)

    return None


def readNBytes(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def main():
    Users = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                header_data = readNBytes(conn, 23)
                if not header_data:
                    print('Connection closed')
                    break

                client_id_bytes, version, code, payload_size = struct.unpack('<16sBHI', header_data)
                client_id = int.from_bytes(client_id_bytes, 'little')
                print(f"Client ID: {client_id_bytes.hex()}", "Version:", version, "Code:", code, "Payload Size:",
                      payload_size)

                if payload_size > 0:
                    payload = readNBytes(conn, payload_size)
                    if not payload:
                        print("Connection closed")
                        break

                    if code == 825:
                        name_bytes = struct.unpack('<255s', payload)
                        name = name_bytes[0].rstrip(b'\x00').decode("utf-8")
                        print("Name:", name)

                        new_uuid = uuid.uuid4()
                        print("Generated new UUID:", new_uuid.hex)

                        response = createResponse(code=1600, client_id=new_uuid.bytes)
                        conn.sendall(response)
                        print("Response sent (1600)")

                    elif code == 826:
                        name_bytes = struct.unpack('<255s160s', payload)
                        name = name_bytes[0].rstrip(b'\x00').decode('utf-8')
                        print('Name:', name)

                        RSA_public_key = name_bytes[1]

                        aes_key = get_random_bytes(32)
                        print(f"AES key: {aes_key.hex()}")

                        RSA_public_key_obj = RSA.importKey(RSA_public_key)

                        cipher_rsa = PKCS1_OAEP.new(RSA_public_key_obj, hashAlgo=SHA256)
                        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

                        response = createResponse(code=1602, client_id=client_id_bytes, aes_key=encrypted_aes_key)
                        conn.sendall(response)
                        print("Response sent (1602)")

                    elif code == 827:
                        print("todo")

                    elif code == 828:
                        name_bytes = struct.unpack(f'<III255s{payload_size - (4 + 4 + 4 + 255)}s', payload)
                        content_size = name_bytes[0]
                        print("Content size:", content_size)

                        orig_file_size = name_bytes[1]
                        print("Original file size:", orig_file_size)

                        packet_info = name_bytes[2]
                        packet_number = packet_info & 0xFFFF
                        print("Packet number:", packet_number)
                        total_packets = packet_info >> 16
                        print("Total packets:", total_packets)

                        name = name_bytes[3].rstrip(b'\x00').decode('utf-8')
                        print("Name:", name)

                        encoded_message_content = name_bytes[4]
                        print("Encoded message content:", encoded_message_content[::].hex())


if __name__ == '__main__':
    main()
