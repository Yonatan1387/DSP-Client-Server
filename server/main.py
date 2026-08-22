HOST = ''
PORT = 1265

import socket
import struct
import uuid

def createResponse(code, client_id=None, aes_key=None, content_size=None, file_name=None, cksum=None):
    if code == 1600 or code == 1604 or code == 1606:
       return struct.pack("<BHI16s", 3, code, 16, client_id)
    elif code == 1602 or code == 1605:
        key_len = len(aes_key)
        structure = f"<BHI16s{key_len}s"
        return struct.pack(structure, 3, code, 0, client_id, aes_key)
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
             print('Client ID:', client_id, "Version:", version, "Code:", code, "Payload Size:", payload_size)

             if payload_size > 0:
                 payload = readNBytes(conn, payload_size)
                 if not payload:
                     print('Connection closed')
                     break

                 if code == 825:
                     name_bytes = struct.unpack('<255s', payload)
                     name = name_bytes[0].rstrip(b'\x00').decode('utf-8')
                     print('Name:', name)

                     new_uuid = uuid.uuid4()
                     print('Generated new UUID:', new_uuid.hex)

                     response = createResponse(code=1600, client_id=new_uuid.bytes)
                     conn.sendall(response)
                     print("Response sent")

if __name__ == '__main__':
    main()
