import ssl, sys, io
import socket
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes 
from endesive.pdf import cms
from endesive import pdf
from cryptography.x509.oid import NameOID
from cryptography.x509 import CertificateBuilder
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization
from binascii import hexlify
import logging
logger = logging.getLogger("Utils")
logger.setLevel(logging.DEBUG)  
# Configure the logger's handler and format
if not logger.hasHandlers():
    handler = logging.StreamHandler()  # Output to console
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
         
        
logger.info(f"Function initialized")

def get_tls_public_key(url, port=443):
    # Create an SSL context

    try:
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
    except:
        return None

    return public_key_pem

def get_tls_certificate(domain, port=443):
    """
    Retrieves the TLS certificate from the given domain.

    Args:
        domain (str): The domain name to connect to.
        port (int): The port to connect to (default is 443 for HTTPS).

    Returns:
        x509.Certificate: The X.509 certificate object.
    """
    # Create an SSL context
    context = ssl.create_default_context()

    # Establish a connection to the server
    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)

    # Convert the DER certificate to an X.509 certificate object
    certificate = x509.load_der_x509_certificate(der_cert, default_backend())

    return certificate

def convert_certificate_to_pem(certificate):
    """
    Converts an X.509 certificate to PEM format.

    Args:
        certificate (x509.Certificate): An X.509 certificate object.

    Returns:
        str: The certificate in PEM format as a string.
    """
    pem_certificate = certificate.public_bytes(encoding=Encoding.PEM)
    return pem_certificate.decode("utf-8")

def pem_string_to_bytes(pem_string, output_format="DER"):
    """
    Converts a public key from a PEM string to bytes.

    Args:
        pem_string (str): The public key in PEM format as a string.
        output_format (str): Desired output format: "DER" or "PEM".
                             Default is "DER".
                             
    Returns:
        bytes: The public key in the requested format as bytes.
    """
    # Load the public key from the PEM string
    public_key = serialization.load_pem_public_key(pem_string.encode())

    # Choose the encoding format
    if output_format.upper() == "DER":
        encoding = serialization.Encoding.DER
    elif output_format.upper() == "PEM":
        encoding = serialization.Encoding.PEM
    else:
        raise ValueError("Invalid output format. Choose 'DER' or 'PEM'.")

    # Convert the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=encoding,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes

def pdf_sign(doc_to_sign, p12_to_use,password):
    date = datetime.utcnow()
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 8192,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        # "sigbutton": True,
        # "sigfield": "Signature1",
        # "auto_sigfield": True,
        # "sigandcertify": True,
        # "signaturebox": (470, 840, 570, 640),
        "signature": "Dokument podpisany cyfrowo ąćęłńóśżź",
        # "signature_img": "signature_test.png",
        "contact": "contact:mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open(p12_to_use, "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), password.encode(), backends.default_backend()
        )
    fname = doc_to_sign
    print(f"fname: {fname}")

    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname = fname.replace(".pdf", "-signed.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)

def pdf_verify_with_domain(pdf_to_verify, domain):


    public_key_pem = get_tls_public_key(domain).decode()
    logger.debug(f"domain: {domain} {public_key_pem}")

    result = pdf_verify_with_public_key(pdf_to_verify,public_key_pem)
    logger.debug(result)
    return result
    


def pdf_verify(pdf_to_verify, pem_to_use, domain):

    print(f"Domain to verify: {domain}")
    tls_pubkey = get_tls_public_key(domain)
    tls_cert = get_tls_certificate(domain)
   
    pem_certificate = tls_cert.public_bytes(encoding=Encoding.PEM).decode("utf-8")
    # print(f"TLS Public Key and Cert: {tls_pubkey} {tls_cert} {pem_to_use} {pem_certificate}")
   
    
    # create_self_signed_certificate_from_public_key(tls_pubkey_pem)
    
   

    trusted_cert_pems = (
        
        open(pem_to_use, "rb").read(),

       
    )
    
    for fname in (

        pdf_to_verify,

    ):
        print(f"Document to verify: {fname}")
        try:
            data = open(fname, "rb").read()
        except:
            continue
        no = 0

        sig_check = pdf.verify(data, trusted_cert_pems )     
        # print(sig_check) 
        if sig_check ==[]:
            raise Exception("\nWARNING!!! This document is not signed or has been altered since signing. DO NOT TRUST!!!\n")
            # print("something is awry!")  
        try:
            for (hashok, signatureok, certok) in pdf.verify(
                data, trusted_cert_pems ):
                print("*" * 10, "signature no:", no)
                print("signature ok?", signatureok)
                print("hash ok?", hashok)
                if not certok:
                    print("\nADVISORY!!! The certificate used to sign this document is not in a trust registry. This document may trusted if the public key used to sign this document originates from the issuing website. Checking this now...")
                else:    
                    print("Signing certificate is trusted.", certok)
        except:
            print("errors")



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
    print(f"public key: {hexlify(public_key.public_bytes(format=PublicFormat.SubjectPublicKeyInfo, encoding=Encoding.DER)).decode()}")

    
    # Generate a random private key for signing the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define subject and issuer (self-signed, so they're the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ontario"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ottawa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "openbalance.app"),
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
    with open("ca/root/certificate.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(Encoding.PEM))

    # Return the PEM-encoded certificate
    return certificate.public_bytes(encoding=Encoding.PEM)

def pdf_verify_with_public_key(pdf_path, public_key_pem):
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

    logger.debug(f"temporary certificate: \n\n {temporary_certificate.decode()}")

    # Read the signed PDF
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Verify the PDF using the temporary certificate
    verification_result = pdf.verify(pdf_data, [temporary_certificate])

    return verification_result

def extract_signatures_and_public_keys(pdf_path):
    """
    Extract public keys from the signatures in a PDF file.

    Args:
        pdf_path (str): Path to the signed PDF.

    Returns:
        list: A list of public keys in PEM format.
    """
    public_keys = []

    # Read the PDF file
    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Verify the PDF signatures
    signature_verification_results = pdf.verify(pdf_data)

    if not signature_verification_results:
        print("No signatures found or verification failed.")
        return public_keys

    print(f"Number of signatures found: {len(signature_verification_results)}")

    for idx, signature_data in enumerate(signature_verification_results):
        print(f"Processing signature {idx + 1}...")

        # signature_data is a tuple; the second element contains signature details
        signature_info = signature_data[1] if isinstance(signature_data, tuple) else None

        if not signature_info:
            print(f" - No signature details found for signature {idx + 1}")
            continue

        # Extract the signing certificate in DER format
        der_cert = signature_info.get("signing_cert", None)
        if not der_cert:
            print(f" - No certificate found for signature {idx + 1}")
            continue

        # Load the DER certificate using cryptography
        certificate = load_der_x509_certificate(der_cert)

        # Extract the public key from the certificate
        public_key = certificate.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        # Print and store the public key
        print(f" - Public Key (PEM format):\n{public_key_pem.decode()}")
        public_keys.append(public_key_pem.decode())

    return public_keys
