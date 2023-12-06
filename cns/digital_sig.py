from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename="private_key.pem"):
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, filename="public_key.pem"):
    with open(filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(filename="private_key.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def load_public_key(filename="public_key.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

if __name__ == "__main__":
    private_key, public_key = generate_key_pair()

    save_private_key(private_key, "private_key.pem")
    save_public_key(public_key, "public_key.pem")

    loaded_private_key = load_private_key("private_key.pem")
    loaded_public_key = load_public_key("public_key.pem")

    message = b"Hello, Digital Signature!"

    signature = sign_message(message, loaded_private_key)
    print(f"Signature: {signature}")

    if verify_signature(message, signature, loaded_public_key):
        print("Signature verified. Message is authentic.")
    else:
        print("Signature verification failed. Message may be tampered.")
