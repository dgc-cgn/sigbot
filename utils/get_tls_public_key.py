import ssl
import socket
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def get_tls_public_key(url, port=443):
    # Create an SSL context
    context = ssl.create_default_context()

    # Connect to the server and get the certificate
    with socket.create_connection((url, port)) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)

    # Load the certificate using cryptography
    certificate = load_der_x509_certificate(der_cert)
    
    # Extract the public key
    public_key = certificate.public_key()
    
    # Convert the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem

# Example Usage
url = "relay.damus.io"
public_key_pem = get_tls_public_key(url)
print(f"Public key for {url}:\n{public_key_pem.decode()}")
