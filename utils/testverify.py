import endesive.pdf
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

def create_temporary_certificate(public_key_pem):
    """
    Creates a proper self-signed X.509 certificate using a random private key.

    Args:
        public_key_pem (str): The public key in PEM format.

    Returns:
        bytes: The DER-encoded certificate.
    """
    # Load the public key from PEM
    public_key = load_pem_public_key(public_key_pem.encode())

    # Generate a random private key for signing the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define subject and issuer (self-signed, so they're the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    # Create the self-signed certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)  # Use the provided public key
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Valid for 1 year
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256())  # Sign with the randomly generated private key
    )

    # Return the DER-encoded certificate
    return certificate.public_bytes(encoding=Encoding.PEM)

def verify_pdf_with_public_key(pdf_path, public_key_pem):
    """
    Verifies a digitally signed PDF using only a public key.

    Args:
        pdf_path (str): Path to the signed PDF file.
        public_key_pem (str): The public key in PEM format.

    Returns:
        dict: Verification details.
    """
    # Create a temporary certificate from the public key
    temporary_certificate = create_temporary_certificate(public_key_pem)
    print(temporary_certificate.decode())

    # Read the signed PDF
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Verify the PDF using the temporary certificate
    verification_result = endesive.pdf.verify(pdf_data, [temporary_certificate])

    return verification_result


# Example Usage
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/tExHbfsG4tWilNXDUIRjoN4JeGW
qSbwaLIsjKwwkze1O5WgA6gWuYwckPd/cbWNCr8DHBscpt32i3gKMKKX8A==
-----END PUBLIC KEY-----
"""


pdf_path = "data/doc-signed.pdf"

# Verify the signed PDF
result = verify_pdf_with_public_key(pdf_path, public_key_pem)

print(result)

