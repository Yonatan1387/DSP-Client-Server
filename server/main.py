HOST = ''
PORT = 1265

import socket
import struct


def readNBytes(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


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