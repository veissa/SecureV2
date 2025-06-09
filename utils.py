from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives import padding as sym_padding

def generate_rsa_keys():
    """Génère une paire de clés RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(user_id, private_key, public_key):
    """Sauvegarde les clés RSA d'un utilisateur"""
    if not os.path.exists('keys'):
        os.makedirs('keys')
    
    # Sauvegarder la clé privée
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'keys/user_{user_id}_private.pem', 'wb') as f:
        f.write(private_pem)
    
    # Sauvegarder la clé publique
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f'keys/user_{user_id}_public.pem', 'wb') as f:
        f.write(public_pem)

def get_user_public_key(user_id):
    """Récupère la clé publique d'un utilisateur"""
    try:
        with open(f'keys/user_{user_id}_public.pem', 'rb') as f:
            return serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except:
        return None

def get_user_private_key(user_id):
    """Récupère la clé privée d'un utilisateur"""
    try:
        with open(f'keys/user_{user_id}_private.pem', 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except:
        return None

def generate_random_aes_key(length=32):
    """Generate a random AES key"""
    return os.urandom(length)

def generate_random_iv():
    """Generate a random initialization vector for AES"""
    return os.urandom(16)

def encrypt_with_aes(data, key, iv):
    """Encrypt data with AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_with_aes(encrypted_data, key, iv):
    """Decrypt data with AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

def encrypt_with_rsa(data, public_key):
    """Encrypt data with RSA public key"""
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(encrypted_data, private_key):
    """Decrypt data with RSA private key"""
    encrypted = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def generate_hmac(data, key):
    """Generate HMAC for data integrity verification"""
    h = hmac.new(key, data, hashlib.sha256)
    return base64.b64encode(h.digest()).decode()

def verify_hmac(data, hmac_value, key):
    """Verify HMAC for data integrity"""
    expected_hmac = generate_hmac(data, key)
    return hmac.compare_digest(hmac_value, expected_hmac)

def sign_message(message, private_key):
    """Signe un message avec une clé privée RSA (SHA-256)."""
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key):
    """Vérifie la signature d'un message avec une clé publique RSA (SHA-256)."""
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
