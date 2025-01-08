from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from os import urandom

# Generate ECDH private and public keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key for sharing
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
# Load serialized public key
def load_public_key(serialized_public_key):
    return serialization.load_pem_public_key(serialized_public_key)

# Derive shared secret using ECDH
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# Derive encryption key from shared secret
def derive_encryption_key(shared_secret):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"encryption-key",
    ).derive(shared_secret)

# Encrypt message using AES
def encrypt_message(encryption_key, message):
    iv = urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv, ciphertext

# Decrypt message using AES
def decrypt_message(encryption_key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Simulation
def main():
    # A generates keys
    A_private_key, A_public_key = generate_keys()
    # B generates keys
    B_private_key, B_public_key = generate_keys()
    # Serialize and share public keys
    A_serialized_public_key = serialize_public_key(A_public_key)
    B_serialized_public_key = serialize_public_key(B_public_key)
    # Load received public keys
    B_loaded_public_key = load_public_key(A_serialized_public_key)
    A_loaded_public_key = load_public_key(B_serialized_public_key)

    # Derive shared secrets
    A_shared_secret = derive_shared_secret(A_private_key, A_loaded_public_key)
    B_shared_secret = derive_shared_secret(B_private_key, B_loaded_public_key)
    # Derive encryption keys
    A_encryption_key = derive_encryption_key(A_shared_secret)
    B_encryption_key = derive_encryption_key(B_shared_secret)

    # Message to encrypt
    message = "IF1220 Matematika Diskrit"
    # A encrypts the message
    iv, ciphertext = encrypt_message(A_encryption_key, message)

    # B decrypts the message
    decrypted_message = decrypt_message(B_encryption_key, iv, ciphertext)

    print("Original Message:", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted Message:", decrypted_message)

main()