import os, rlp, ethereum, random, string 
import transactions
from py_ecc.secp256k1 import secp256k1 
from Crypto.Cipher import AES
from Crypto.Util import Counter
from attrdict import AttrDict
from pathlib import Path

from web3.utils.transactions import (
    get_buffered_gas_estimate,
)

from eth_utils import (
    is_hex_address, 
    to_checksum_address,
    add_0x_prefix,
    remove_0x_prefix,
    is_hex, is_string
)

from rlp.utils import (
    decode_hex, 
    encode_hex
)

def is_transaction_hash(value):
    """
    Checks if the given string is an address in hexidecimal encoded form.
    """
    if not is_string(value):
        return False
    elif len(value) not in {66, 64}:
        return False
    elif is_hex(value):
        return True
    else:
        return False

def get_default_ipc_path(testnet=False):
    home = str(Path.home()) + '/'
    folder = ''
    if os.name == 'nt':
        folder = 'AppData/Roaming/Ethereum/' 
    if os.name == 'mac':
        folder = 'Library/Ethereum/' 
    else:
        folder = '.ethereum/' 
    network = ''
    if testnet:
        network = 'testnet/'    
    return home + folder + network + 'geth.ipc'

def web3tx_to_ethtx(web3tx):
    to = '' if web3tx.to is None else \
                ethereum.utils.int_to_bytes(int(web3tx.to[2:], 16))
    input_data = ethereum.utils.remove_0x_head(web3tx.input)
    input_data = ethereum.utils.decode_hex(input_data)
    return transactions.Transaction(nonce=web3tx.nonce, 
                gasprice=web3tx.gasPrice, startgas=web3tx.gas, to=to, 
                value=web3tx.value,
                data=input_data,
                v=web3tx.v,
                r=ethereum.utils.bytes_to_int(web3tx.r),
                s=ethereum.utils.bytes_to_int(web3tx.s))

def rawtx_to_ethtx(raw_tx_hex):
    (nonce, gasprice, gaslimit, to, value, data, v, r, s) = \
        map(ethereum.utils.bytes_to_int, rlp.hex_decode(raw_tx_hex))
    return transactions.Transaction(nonce=nonce, 
                gasprice=gasprice, startgas=gaslimit, 
                to=ethereum.utils.int_to_bytes(to), 
                value=value,
                data=ethereum.utils.int_to_bytes(data),
                v=v, r=r, s=s)

# PKCS#7 padding
def pad(message, block_size):
    padded = message
    last_block = len(message) % block_size
    to_pad = block_size - last_block
    padded = padded + bytes([to_pad] * to_pad)
    return padded

def unpad(message, block_size):
    length = len(message)
    if length == 0:
        return message
    to_pad = message[length - 1]
    if to_pad > block_size:
        return message
    if length < to_pad:
        return message
    pad_start = length - to_pad
    for c in message[pad_start:]:
        if c != to_pad:
            return message
    return message[:pad_start]

def encode_point(point):
    return ethereum.utils.encode_int32(point[0]) + ethereum.utils.encode_int32(point[1])

def decode_point(pubkey):
    return (ethereum.utils.bytes_to_int(pubkey[:32]), ethereum.utils.bytes_to_int(pubkey[32:64]))

def encrypt(pubkey, plaintext_bytes):
    padded = pad(plaintext_bytes, AES.block_size)
    r = random.SystemRandom().randrange(1, secp256k1.N)
    R = secp256k1.multiply(secp256k1.G, r)
    R_bytes = encode_point(R)
    S = secp256k1.multiply(decode_point(pubkey), r)[0]
    key_enc = ethereum.utils.sha3(ethereum.utils.int_to_bytes(S+1))
    prefix_bytes = random.getrandbits(64).to_bytes(8, byteorder='big')
    ctr = Counter.new(64, prefix=prefix_bytes)
    cipher = AES.new(key=key_enc, mode=AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(padded)
    return rlp.encode([R_bytes, prefix_bytes, ciphertext])

def decrypt(privkey, encrypted_bytes):
    R_bytes, prefix_bytes, ciphertext = rlp.decode(encrypted_bytes)
    S = secp256k1.multiply(decode_point(R_bytes), privkey)[0]
    key_enc = ethereum.utils.sha3(ethereum.utils.int_to_bytes(S+1))
    ctr = Counter.new(64, prefix=prefix_bytes)
    cipher = AES.new(key=key_enc, mode=AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)