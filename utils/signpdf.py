import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import endesive.pdf

def sign_pdf(input_pdf, output_pdf, private_key_file, certificate_file):
    # Load the private key
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Add password if your private key is encrypted
        )
    
    # Load the certificate
    with open(certificate_file, "rb") as cert_file:
        certificate = load_pem_x509_certificate(cert_file.read())

    # Extract the public bytes of the certificate
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)

    # Define metadata for the signature
    dct = {
        'sigpage': 0,  # Page number to apply the signature (0-indexed)
        'sigbutton': True,  # Create a visible signature button
        'sigfield': 'Signature1',  # Name of the signature field
        'signaturebox': (100, 100, 400, 200),  # Signature box coordinates (x1, y1, x2, y2)
        'signingdate': datetime.datetime.utcnow(),  # UTC signing date
        'reason': 'Document approval',  # Reason for signing
        'location': 'New York, USA',  # Location of signing
        'contact': 'contact@example.com',  # Contact information
    }

    # Read the input PDF
    with open(input_pdf, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    # Sign the PDF using the private key and certificate
    signed_pdf = endesive.pdf.cms.sign(
        pdf_data,
        dct,
        private_key,
        certificate_der,
        None
    )

    # Save the signed PDF
    with open(output_pdf, "wb") as output_file:
        output_file.write(signed_pdf)

    print(f"PDF signed and saved as: {output_pdf}")

# Example Usage
sign_pdf(
    input_pdf="data/document.pdf",
    output_pdf="data/signed_document.pdf",
    private_key_file="ca/private_key.pem",
    certificate_file="ca/certificate.pem"
)
