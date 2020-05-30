from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from netfilterqueue import NetfilterQueue

import dpkt
import random
import socket
import struct
import sys
import time

keya_text = b'4p\xf8ipfD(\x99\xbb\x1d\xa2k\xeb\xaf\x05\xf0\x16\xdfGK\xb8V\xd4\xf3\x17?]S\xa0{B'
keya = AESGCM(keya_text)


pubkey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjggW52Zpc3rQY1sQUmju\nOqKkmkQkPFdftVj1z3yspbtC2VjrOmu8MY99tR25aPU+t7TjIlVCyJbq9f6Gpt8w\n13tBqk/zi3igc+pfjs4pqyNSWcQlV2a+3l68Zp8UGWaSIKoabs6jnM+8/u0EzlAq\nwpG/jHrc/js/PuCO4ge+6oMZ9zcn/iEc1WAGHI649VeqK/yUOpPfzqsfZE52WkrH\nBLr6sxp8E/uXA8uAeF1+p0qiL7EjrF2lvDEmA7JrTLaqnwFCfRyY4IhGNYf8dAB1\n3gKbzoeE5KBLZgVEFeWuuJIuPligdlCiKwJwHm7DSS/ujoKmwx2Z3O1DgSv+65K6\nZQIDAQAB\n-----END PUBLIC KEY-----'
asymmetrickeyx = RSA.importKey(pubkey)

pubkeys = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5CGUJIk41oMpDYzZpIS\n1YV+zWje9JhP71pYmFc6bnXysYQ5L25FVQv4NJoBmXWFWMr+gadokWmKZBUoqlTZ\ngrh/42pY8Pz+WJXrNJa5wyE6rv9HoS9MGq5sS4nvt48uKzMoHfn7zrwFSifXKYZP\nvv+Fq6+fCRZh28s5Kkv2PM1xbu1zjheC0GzPwEltqJP54/axI2W4CvWraG3SLiwy\nYT3aVpSLWRInoqhHDfMQfRSsDHaUKTT01vrSPif55FCUrGbP+4rX7c/n6huG/DJN\nsBkMGnJG9A1JO0fz8YWisgdmNI8+8rIcgYRGmCLhoZq868Sn9TAX5FgdjY/3SYbD\nBQIDAQAB\n-----END PUBLIC KEY-----'
asymmetrickeys = RSA.importKey(pubkey)



sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

initial_time = 0
final_time = 0

# Run 1000 times
counter = 1000

client_id = 1
server_id = 0

def run():
    ip6_packet = dpkt.ip6.IP6()

    ip6_packet.src = socket.inet_pton(socket.AF_INET6, '0:0:0:0:0:0:0:0')
    ip6_packet.dst = socket.inet_pton(socket.AF_INET6, '2100::106')

    data = "Hello!"

    id_From =  struct.pack(">I", client_id)
    id_to = struct.pack(">I", server_id)


    header = pubkey + id_From + id_to + asymmetrickeys.encrypt(data, 0)[0]
    
    ip6_packet.nxt = 99
    ip6_packet.p = 99
    ip6_packet.all_extension_headers = []
    ip6_packet.extension_hdrs = []
    ip6_packet.data = header_a
    ip6_packet.plen = len(ip6_packet.data)

    sockfd.sendto(bytes(ip6_packet), ('2100::106', 0))

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    client_id = pkt.data[-4:]
    print("\n")
    print("this is the id")
    print(struct.unpack(">I",client_id)[0])
    pkt.data = pkt.data[:-4]
    ci = struct.unpack(">I", pkt.data[:4])[0]
    
    client_id = pkt.data[-4:len(pkt.data)]
    print(struct.unpack(">I", client_id)[0])

    # --- Header 2
    header_2 = pkt.data[4:]

    derived_key = parse_header_2_block(header_2, asymmetrickeyb, ecdhe_cb)
    nonce = struct.unpack(">I", header_2[288:292])[0]
    header_2 = bytes(derived_key.decrypt(bytes(nonce), header_2[292:], ''))

    derived_key = parse_header_2_block(header_2, asymmetrickeyx, ecdhe_cx)
    nonce = struct.unpack(">I", header_2[288:292])[0]
    header_2 = bytes(derived_key.decrypt(bytes(nonce), header_2[292:], ''))

    derived_key = parse_header_2_block(header_2, asymmetrickeya, ecdhe_ca)

    packet.drop()
    


   

def parse_header_2_block(header_2, asymm_key, symm_key):
    ecdhe = header_2[:288]

    if not verify_signature(asymm_key, ecdhe):
        raise Exception("Signature failure")

    ecdhe = ecdhe[:32]

    shared_key = symm_key.exchange(X25519PublicKey.from_public_bytes(ecdhe))

    derived_key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        info=None,
        salt=None,
        backend=default_backend()
    ).derive(shared_key)

    derived_key = AESGCM(derived_key)

    return derived_key

def verify_signature(key, text):
    msg = text[:32]

    h = SHA512.new(msg)

    signature = text[32:]

    try:
        PKCS1_v1_5.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def is_icmp_neighbour_message(ip_packet):
    if ip_packet.nxt != 58:
        return False

    icmp_packet = ip_packet.data

    if icmp_packet.type == 135 or icmp_packet.type == 136:
        return True

    return False

nfqueue = NetfilterQueue()

# 2 is the iptables rule queue number, modify is the callback function
nfqueue.bind(2, modify)

initial_time = time.time()

run()

nfqueue.run()

