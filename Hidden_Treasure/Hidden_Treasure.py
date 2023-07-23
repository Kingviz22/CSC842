from scapy.all import *
import base64
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Function to encrypt data
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def main(target_ip, target_port, data):
    # Generate a random 16 byte AES key
    key = get_random_bytes(16)

    # Make sure the data is bytes
    if isinstance(data, str):
        data = data.encode()

    # Encrypt the data
    encrypted_data = encrypt_data(data, key)
    
    # Base64 encode the encrypted data
    encoded_data = base64.b64encode(encrypted_data)
    
    # We can store up to 2 bytes in IP id field, 2 bytes in the TCP windows field, and 2 bytes in TCP urgptr field
    # So split the data into chunks of 2 bytes
    data_chunks = [encoded_data[i:i+2] for i in range(0, len(encoded_data), 2)]
    
    # Split the key into chunks of 2 bytes
    key_chunks = [key[i:i+2] for i in range(0, len(key), 2)]

    # Merge data and key chunks
    chunks = data_chunks + key_chunks

    for i, chunk in enumerate(chunks):
        if len(chunk) == 2:
            id_value, win_value = chunk[0], chunk[1]
        else:  # We have only one byte left
            id_value, win_value = chunk[0], 0

        # Create the packet
        ip_packet = IP(dst=target_ip, id=id_value)
        tcp_packet = TCP(dport=target_port, window=win_value, urgptr=0 if i < len(data_chunks) else int.from_bytes(chunk, byteorder='big'), options=[('NOP', None)])

        # Send the packet
        send(ip_packet/tcp_packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP Packet Steganography')
    parser.add_argument('--target_ip', type=str, required=True, help='Target IP Address')
    parser.add_argument('--target_port', type=int, required=True, help='Target Port')
    parser.add_argument('--data', type=str, required=True, help='Data to Hide')

    args = parser.parse_args()
