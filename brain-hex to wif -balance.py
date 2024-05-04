import hashlib
import base58
import ecdsa
import requests
import bech32
from binascii import hexlify, unhexlify

def text_to_private_key(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.digest()

def hex_to_private_key(hex_string):
    hex_string = hex_string.rjust(64, '0')
    return unhexlify(hex_string)

def private_key_to_wif(private_key, compressed=True):
    extended_key = b'\x80' + private_key
    if compressed:
        extended_key += b'\x01'
    sha256 = hashlib.sha256()
    sha256.update(extended_key)
    hashed_key = sha256.digest()
    sha256 = hashlib.sha256()
    sha256.update(hashed_key)
    hashed_key = sha256.digest()
    checksum = hashed_key[:4]
    wif_key = base58.b58encode(extended_key + checksum)
    return wif_key.decode('utf-8')

def private_key_to_public_key(private_key, compressed=True):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x04' + vk.to_string()
    if compressed:
        pubkey = b'\x02' + pubkey[1:33] if pubkey[64] % 2 == 0 else b'\x03' + pubkey[1:33]
    return pubkey

def pubkey_to_address(pubkey, p2sh=False, compressed=True):
    sha256 = hashlib.sha256()
    sha256.update(pubkey)
    hashed_pubkey = sha256.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashed_pubkey)
    hashed_pubkey = ripemd160.digest()
    if p2sh:
        redeemScript = b'\x00\x14' + hashed_pubkey
        sha256 = hashlib.sha256()
        sha256.update(redeemScript)
        hashed_redeemScript = sha256.digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashed_redeemScript)
        hashed_redeemScript = ripemd160.digest()
        network_byte = b'\x05'
        extended_pubkey = network_byte + hashed_redeemScript
    else:
        network_byte = b'\x00'
        extended_pubkey = network_byte + hashed_pubkey
    sha256 = hashlib.sha256()
    sha256.update(extended_pubkey)
    hashed_pubkey = sha256.digest()
    sha256 = hashlib.sha256()
    sha256.update(hashed_pubkey)
    hashed_pubkey = sha256.digest()
    checksum = hashed_pubkey[:4]
    address = base58.b58encode(extended_pubkey + checksum)
    return address.decode('utf-8')

def pubkey_to_p2wpkh_address(pubkey):
    sha256 = hashlib.sha256()
    sha256.update(pubkey)
    hash_pubkey = sha256.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hash_pubkey)
    pubkey_hash = ripemd160.digest()
    return bech32.encode('bc', 0, pubkey_hash)

def pubkey_to_p2sh_p2wpkh_address(pubkey):
    sha256 = hashlib.sha256()
    sha256.update(pubkey)
    hash_pubkey = sha256.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hash_pubkey)
    pubkey_hash = ripemd160.digest()
    redeem_script = b'\x00\x14' + pubkey_hash
    sha256 = hashlib.sha256()
    sha256.update(redeem_script)
    hash_redeem_script = sha256.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hash_redeem_script)
    script_hash = ripemd160.digest()
    network_byte = b'\x05'
    extended_pubkey = network_byte + script_hash
    return base58.b58encode(extended_pubkey).decode('utf-8')

def get_address_balance(address):
    try:
        response = requests.get(f'https://blockchain.info/rawaddr/{address}')
        if response.status_code == 200:
            data = response.json()
            final_balance = data.get('final_balance', 0)
            return final_balance / 100000000  # Convert satoshis to bitcoins
        else:
            return None
    except Exception as e:
        print(f"An error occurred while fetching balance: {e}")
        return None

print("Brain wallet, hex to WIF changer, address generator")
print("By UFODIA - https://millionmac.com")
print()

while True:
    input_type = input("Enter '1' for text input or '2' for hex input: ")
    if input_type == '1':
        text = input("Please enter a sentence: ")
        private_key = text_to_private_key(text)
    elif input_type == '2':
        hex_string = input("Please enter the hex string of the private key: ")
        private_key = hex_to_private_key(hex_string)
    else:
        print("Invalid input!")
        continue

    private_key_hex = hexlify(private_key).decode('utf-8')
    print("#####################################################################")
    print("Private Key (hex):", private_key_hex)
    print("..........................................")

    # Compressed keys and addresses
    private_key_wif_compressed = private_key_to_wif(private_key, compressed=True)
    public_key_compressed = private_key_to_public_key(private_key, compressed=True)
    p2pkh_address_compressed = pubkey_to_address(public_key_compressed, p2sh=False, compressed=True)
    p2sh_address_compressed = pubkey_to_address(public_key_compressed, p2sh=True, compressed=True)
    bech32_address = pubkey_to_p2wpkh_address(public_key_compressed)
    p2sh_p2wpkh_address = pubkey_to_p2sh_p2wpkh_address(public_key_compressed)

    print("\nCompressed Private Key (WIF):", private_key_wif_compressed)
    print("Compressed P2PKH Address:", p2pkh_address_compressed)
    print("Compressed P2SH Address:", p2sh_address_compressed)
    print("Bech32 Address:", bech32_address)
    print("P2SH-P2WPKH Address:", p2sh_p2wpkh_address)

    # Uncompressed keys and addresses
    private_key_wif_uncompressed = private_key_to_wif(private_key, compressed=False)
    public_key_uncompressed = private_key_to_public_key(private_key, compressed=False)
    p2pkh_address_uncompressed = pubkey_to_address(public_key_uncompressed, p2sh=False, compressed=False)
    p2sh_address_uncompressed = pubkey_to_address(public_key_uncompressed, p2sh=True, compressed=False)

    print("\nUncompressed Private Key (WIF):", private_key_wif_uncompressed)
    print("Uncompressed P2PKH Address:", p2pkh_address_uncompressed)
    print("Uncompressed P2SH Address:", p2sh_address_uncompressed)

    # Get balance for the uncompressed P2PKH address
    p2pkh_balance_uncompressed = get_address_balance(p2pkh_address_uncompressed)
    if p2pkh_balance_uncompressed is not None:
        print(f"Balance of Uncompressed P2PKH Address ({p2pkh_address_uncompressed}): {p2pkh_balance_uncompressed} BTC")
    # Get balance for the uncompressed P2SH address
    p2sh_balance_uncompressed = get_address_balance(p2sh_address_uncompressed)
    if p2sh_balance_uncompressed is not None:
        print(f"Balance of Uncompressed P2SH Address ({p2sh_address_uncompressed}): {p2sh_balance_uncompressed} BTC")
    print("#####################################################################")

    # Ask the user whether to continue or exit
    user_choice = input("Type 'exit' to quit or press enter to start again: ").strip().lower()
    if user_choice == 'exit':
        break
