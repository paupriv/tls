import socket
import math
import random
import os
import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 1337  # Port to listen on (non-privileged ports are > 1023)

def dec2hex(n):
    s = hex(n)
    s = s[2:]
    if len(s) != 2:
        s = "0" + s
    return s

def hex2dec(ss):
    d = 0

    p = len(ss) - 1
    for x in range(0, len(ss)):
        c = ss[x]
        if (c.isdigit() == False):
            c = ord(c.lower()) - 87

        d += pow(16, p) * int(c)
        p -= 1
    
    return d

def hex2text(ss):
    text = ""
    for i in range(0, len(ss)):
        if i % 2 == 0:
            n = hex2dec(ss[i:i+2])
            text += chr(n)
    return text

def random_str(n):
    ss = ""

    for x in range(n):
        dec = random.randint(0, 256)
        ss += dec2hex(dec)
    return ss
    
def connection(sock):

    record_header = sock.recv(5).hex()

    handshake_record_type = record_header[0:2]
    protocol_version = record_header[2:6]

    len_handshake_message = hex2dec(record_header[6:10])




    handshake_header = sock.recv(4).hex()

    handshake_message_type = handshake_header[0:2]
    len_client_hello_data = hex2dec(handshake_header[2:8])

    
    #Begin of client hello
    
    client_hello = sock.recv(len_client_hello_data).hex()
    client_hello_index = 0

    client_version = client_hello[client_hello_index:client_hello_index+4]
    client_hello_index += 4

    client_random = client_hello[client_hello_index:client_hello_index + 64]
    client_hello_index += 64
    
    len_session_id = hex2dec(client_hello[client_hello_index:client_hello_index+2])
    client_hello_index += 2
    
    session_id = client_hello[client_hello_index:client_hello_index + len_session_id*2]
    client_hello_index += len_session_id*2

    len_cipher_suite = hex2dec(client_hello[client_hello_index:client_hello_index+4])
    client_hello_index += 4

    cipher_suites = client_hello[client_hello_index:client_hello_index+len_cipher_suite*2]
    client_hello_index += len_cipher_suite*2

    len_compression_methods = hex2dec(client_hello[client_hello_index:client_hello_index+2])
    client_hello_index += 2

    compression_methods = client_hello[client_hello_index:client_hello_index+len_compression_methods*2]
    client_hello_index += len_compression_methods*2

    len_extensions = hex2dec(client_hello[client_hello_index:client_hello_index+4])
    client_hello_index += 4

    extensions = client_hello[client_hello_index:client_hello_index + len_extensions*2]
    client_hello_index += len_extensions*2

    # Parse Extensions

    client_public_key = ""

    extension_index = 0
    while(extension_index != len(extensions)):
        if extensions[extension_index:extension_index+4] == "0000":
            extension_index += 4
            # Server Name

            len_extension_server_name = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4
            extension_server_name = extensions[extension_index:extension_index+len_extension_server_name*2]
            extension_index += len_extension_server_name*2

            len_list_entry = hex2dec(extension_server_name[0:4])
            list_entry = extension_server_name[4:4+len_list_entry*2]
            
            list_entry_type = list_entry[0:2]

            len_hostname = hex2dec(list_entry[2:6])
            hostname = list_entry[6:6+len_hostname*2]

            print("Hostname: " + hex2text(hostname))
        
        elif extensions[extension_index:extension_index+4] == "000b":
            extension_index += 4
            
            len_extension_ex_point_formats = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_format_types = hex2dec(extensions[extension_index:extension_index+2])
            extension_index += 2

            format_types = extensions[extension_index:extension_index+len_format_types*2]
            extension_index += len_format_types*2

        elif extensions[extension_index:extension_index+4] == "000a":
            extension_index += 4



            len_supported_groups = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_curves_list = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            curves_list = extensions[extension_index:extension_index+len_curves_list*2]
            extension_index += len_curves_list*2


            # Problem solve
            # Unknown string sample "33740000 0010 000e 000c 02683208 687474702f312e31"

            extension_index = extensions.index("0016")
            # Skipped string, experimental

        elif extensions[extension_index:extension_index+4] == "0016":
            extension_index += 4

            len_enc_mac = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

        elif extensions[extension_index:extension_index+4] == "0017":
            extension_index += 4

            len_master_secret = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            # Unknown string sample "00310000"

            extension_index = extensions.index("000d")
            # Skipped string, experimental

        elif extensions[extension_index:extension_index+4] == "000d":
            extension_index += 4

            len_sig_alg = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_list = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            list_data = extensions[extension_index:extension_index+len_list*2]
            extension_index += len_list*2

        elif extensions[extension_index:extension_index+4] == "002b":
            extension_index += 4

            len_data = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_version = hex2dec(extensions[extension_index:extension_index+2])
            extension_index += 2

            version = extensions[extension_index:extension_index+len_version*2]
            extension_index += len_version*2

        elif extensions[extension_index:extension_index+4] == "002d":
            extension_index += 4

            len_data = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_models = hex2dec(extensions[extension_index:extension_index+2])
            extension_index += 2

            models = extensions[extension_index:extension_index+len_models*2]
            extension_index += len_models*2

        elif extensions[extension_index:extension_index+4] == "0033":
            extension_index += 4

            len_data_ex = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            len_data = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            type = extensions[extension_index:extension_index+4]
            extension_index += 4

            len_pub_key = hex2dec(extensions[extension_index:extension_index+4])
            extension_index += 4

            client_public_key_hex = extensions[extension_index:extension_index+len_pub_key*2]
            extension_index += len_pub_key*2

            #print("Client public key: " + client_public_key_hex)
            #print(len(client_public_key))

        else:
            extension_index = len(extensions)

        #print(extensions[extension_index:extension_index+4])
        #print(extensions[extension_index:])

    # End of client hello


    client_public_key_hex = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"

    server_private_key = X25519PrivateKey.generate()
    server_private_key = X25519PrivateKey.from_private_bytes(bytearray.fromhex("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
    server_private_key_hex = server_private_key.private_bytes(encoding=serialization.Encoding.Raw,format=serialization.PrivateFormat.Raw,encryption_algorithm=serialization.NoEncryption()).hex()

    server_public_key = server_private_key.public_key()
    server_public_key_hex = server_public_key.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()

    client_public_key = X25519PublicKey.from_public_bytes(binascii.unhexlify(client_public_key_hex))
    client_shared_key = server_private_key.exchange(client_public_key)
    #shared_key_hex =
    derived_key = HKDF(algorithm=hashes.SHA384(),length=32,salt=None,info=b'test data',).derive(shared_key)


    print("Client pub key: " + client_public_key_hex)
    print("Server priv key: " + server_private_key_hex)
    print("Server pub key: " + server_public_key_hex)

    print(shared_key)

    # Build server hello

    server_hello = ""

    # -> Extension - Key Share
    server_hello_ex_key_share = ""
    server_hello_ex_key_share = server_public_key_hex + server_hello_ex_key_share
    server_hello_ex_key_share = "00" + dec2hex(int(len(server_hello_ex_key_share)/2)) + server_hello_ex_key_share
    server_hello_ex_key_share = "001d" + server_hello_ex_key_share
    server_hello_ex_key_share = "00" + dec2hex(int(len(server_hello_ex_key_share)/2)) + server_hello_ex_key_share
    server_hello_ex_key_share = "0033" + server_hello_ex_key_share

    # -> Extension - Supported Versions
    server_hello_ex_sup_ver = ""
    server_hello_ex_sup_ver = "0304" + server_hello_ex_sup_ver
    server_hello_ex_sup_ver = "0002" + server_hello_ex_sup_ver
    server_hello_ex_sup_ver = "002b" + server_hello_ex_sup_ver

    server_hello = server_hello_ex_sup_ver + server_hello_ex_key_share
    
    # -> Extensions length
    server_hello = "00" + dec2hex(int(len(server_hello)/2)) + server_hello

    # -> Compression Method
    server_hello = "00" + server_hello

    # TODO: Select from client provied cipher suites
    # -> Cipher Suite
    server_hello = "1302" + server_hello

    # -> Session ID
    server_hello = session_id + server_hello
    server_hello = dec2hex(int(len(session_id)/2)) + server_hello
    

    # -> Server Random
    server_random = random_str(32)
    server_hello = server_random + server_hello

    # -> Server Version
    server_hello = "0303" + server_hello

    # -> Handshake Header
    server_hello = "0000" + dec2hex(int(len(server_hello)/2)) + server_hello
    server_hello = "02" + server_hello

    # -> Record Header
    server_hello = "00" + dec2hex(int(len(server_hello)/2)) + server_hello
    server_hello = "0303" + server_hello
    server_hello = "16" + server_hello

    sock.send(bytearray.fromhex(server_hello))





def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        connection(conn)

server()





    

#print(random_str(32))








