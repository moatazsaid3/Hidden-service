from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from netfilterqueue import NetfilterQueue

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import dpkt
import socket
import struct


key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAruJ2zpbGhjr+LS1eiz2fMvBcOcv55vWfND+/Alz9bpuDD2xM\nMDVvKO9LTRjEwMzyJi6i5GBpcsDblDbu3LmNc2iGWW9FDmOBYDAWBQtr3UO61KMB\nIT2iT7NcQqhPZYFy+lQgAYH6WjASlYLq/4GP2qKXw1MDA8NAntFq3W3aHNWlIN2w\nddRWGUa6d/fl1lLKT4L6DsFftuY7GQfzrBOtzPBxCVv8w4mU2r+Ixergy6Qjz96G\nXPiQvze2ZaRxW5+Ob+P8TW+JOufyEzQB3r4wddjUjoHiwzj72w80oDMUS3BtiVuJ\ng0GVkJlVmKD9SuBZdIkhAQqF9WKAhy9ouJxDIwIDAQABAoIBAHXFYEjDVLH0bFM0\nKGUQfHMrVpA9gu88HZhsDU+kG68u3tW2EqCse01PyKAEvAsyeSepZFzzaE+0/KoV\nTEosUsuTalY0DocgD3IdL9b52AvLnrevhgVColmV6d2hxsYOpMVbfapGQ7gUg49X\n+LVUJPIRaK5K6s7P4GaTlKnFXornXuLRgyTFR+PLDg3/zr9MryY0ZyrA8QKhkRCR\nqnVIi9SoPgq5jGBkCW8OKH9Ad3+BfvbRTPLbNScajq6m41mM8hgrDIB6M+YQLval\nVClrW/00nPBJIu+FNWp2JpGb+OxhcSLlpTxxKw3+Nq19BgeNeVrmlaZbTEkyaalx\n9/RB2jECgYEAwFgY4GiYIrS1iMdysiedoKyEKvRMcuRs9ZFJCtHaBTxPh7j4oSS+\nmlm0l0eCODQ5ttE9s+/liwTjOlFrJXem5tdll7IEBPzh3H3mb5S2I/HkLXpyXh93\nb0e9P7CzaUQv6YJ/FESJfQKwopqXLfqrjolHUH6bedvkaD5XSqPU/H0CgYEA6MMm\nzo2z2Zg4mQ9q5eQfQ1ndcrS8/fiRcy32CxfbDqKt6X54RKaNNDxvxUA4wOhK2FNZ\nWXAf3Vq9O02stBmc3o4OyYQBSKJ3DJllf+ugAK3a6LwovkgJlgs4Jm1MEz/9lKA7\n4C7M12tdh4B1eF8vn/s7aFOnJWkAgjnbme63cB8CgYEAvZaYfqnaO2tP/FBLl5tA\n3dzuMcC3kg/h7nOUQZvzgHGgGrGSMJQdY9rEDNEpY+jmcnLwlOoDofHhX9xc9oNn\n+eWad9m56IiywDlA5/73QZruRH2LOYdenEtkGOE9Fqdlao98XyfnNVdvb/dcyK9q\nZoadypPhAE5kZvP76tBt4akCgYA+4aHVQXDqAvafWwvtCWDsyBVMTMmV7xYUQMFs\no8g5Pveu0czZ9wjEqOMlLcFnVBoMMRA9Wk4xdbcTk1tp2FWJxmT2SeQy5Dk3PSWv\nlk9Gf7FZGKQFK97zGxrTPsnDlZEDGvqyCNKsC8Rbu/eASm7KUIvvFlJch+5sQAc0\nocoKzwKBgQCPhnyC0RxYGyrM9EfFdXHkVk+M40nl8SJkrDojpzCrtGkkz1I49HvO\no/tjB+9nDCzp12JjKnaJb453DOiHep6HJsgQWjtQgkjI6l++80j+74Cc3qXls3zP\n1QMXfOSgq9VLLot9sQRnbyisUOVkYJEwMb/hKoOq7FPr2Z/rcXNa2A==\n-----END RSA PRIVATE KEY-----'
asymmetrickeyc = RSA.importKey(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def run():
    ip6_packet = dpkt.ip6.IP6()

    ip6_packet.src = socket.inet_pton(socket.AF_INET6, '0:0:0:0:0:0:0:0')
    ip6_packet.dst = socket.inet_pton(socket.AF_INET6, '2100::105')
    
    #this should be encrypted using the directory's public key 
    header_a = "A server's HOSTNAME"

    ip6_packet.nxt = 99
    ip6_packet.p = 99
    ip6_packet.all_extension_headers = []
    ip6_packet.extension_hdrs = []
    ip6_packet.data = header_a
    ip6_packet.plen = len(header_a)
    

    sockfd.sendto(bytes(ip6_packet), ('2100::105', 0))


def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    aes_key_text = pkt.data[:256]
    aes_key_text = asymmetrickeyc.decrypt(aes_key_text)
    nonce = struct.unpack(">I", pkt.data[256:260])[0]
    ecdhe = pkt.data[260:292]
    ci = struct.unpack(">I", pkt.data[292:296])[0]
    
    aes_key = AESGCM(aes_key_text)

    decrypted_block = bytes(aes_key.decrypt(bytes(nonce), pkt.data[296:], ''))

    ip_a = decrypted_block[:16]

    pkt.data = decrypted_block[16:] 
    pkt.plen = len(pkt.data)
    
    pkt.dst = ip_a

    sockfd.sendto(bytes(pkt), (socket.inet_ntop(socket.AF_INET6, ip_a), 0))

    packet.drop()


def is_icmp_neighbour_message(ip_packet):
    if ip_packet.nxt != 58:
        return False

    icmp_packet = ip_packet.data

    if icmp_packet.type == 135 or icmp_packet.type == 136:
        return True

    return False

def sign(message, priv_key):
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA512.new()
    digest.update(message)
    return signer.sign(digest)


nfqueue = NetfilterQueue()

#run()

# 1 is the iptables rule queue number, modify is the callback function
nfqueue.bind(2, modify)

nfqueue.run()
